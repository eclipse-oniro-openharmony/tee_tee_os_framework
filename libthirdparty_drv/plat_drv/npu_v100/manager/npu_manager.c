/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu manager
 */

#include "npu_manager.h"
#include <string.h>
#include <list.h>

#include <errno.h>
#include <hmdrv_stub.h>        //  hack for `HANDLE_SYSCALL
#include "drv_pal.h"
#include "drv_log.h"
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */

#include "npu_proc_ctx.h"
#include "npu_manager_ioctl_services.h"
#include "npu_custom_info_share.h"
#include "npu_ioctl_services.h"
#include "npu_io_cmd_share.h"
#include "npu_calc_channel.h"
#include "npu_calc_cq.h"
#include "npu_stream.h"
#include "npu_shm.h"
#include "npu_common.h"
#include "npu_devinit.h"
#include "npu_pm.h"
#include "npu_firmware.h"
#include "npu_recycle.h"
#include "npu_mailbox_msg.h"
#include "npu_manager_common.h"
#include "npu_platform.h"
#include "npu_semaphore.h"
#include "npu_cma.h"
#include "npu_adapter.h"

static struct npu_manager_info *g_dev_manager_info;

static int (*npu_dev_ioctl_call[DEVDRV_MAX_CMD])
	(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size) = {NULL};

static npu_io_cmd_to_name_t s_io_cmd_func_name_map[] = {
	{ _IOC_NR(DEVDRV_ALLOC_STREAM_ID),         "npu_ioctl_alloc_stream" },
	{ _IOC_NR(DEVDRV_FREE_STREAM_ID),          "npu_ioctl_free_stream" },
	{ _IOC_NR(DEVDRV_GET_OCCUPY_STREAM_ID),    "npu_ioctl_get_occupy_stream_id" },
	{ _IOC_NR(DEVDRV_ALLOC_EVENT_ID),          "npu_ioctl_alloc_event" },
	{ _IOC_NR(DEVDRV_FREE_EVENT_ID),           "npu_ioctl_free_event" },
	{ _IOC_NR(DEVDRV_ALLOC_MODEL_ID),          "npu_ioctl_alloc_model" },
	{ _IOC_NR(DEVDRV_FREE_MODEL_ID),           "npu_ioctl_free_model" },
	{ _IOC_NR(DEVDRV_ALLOC_TASK_ID),           "npu_ioctl_alloc_task" },
	{ _IOC_NR(DEVDRV_FREE_TASK_ID),            "npu_ioctl_free_task" },
	{ _IOC_NR(DEVDRV_MAILBOX_SEND),            "npu_ioctl_mailbox_send" },
	{ _IOC_NR(DEVDRV_REPORT_WAIT),             "npu_ioctl_report_wait" },
	{ _IOC_NR(DEVDRV_GET_TS_TIMEOUT_ID),       "npu_ioctl_get_ts_timeout" },
	{ _IOC_NR(DEVDRV_SET_SECURE_FLAG),         "npu_ioctl_set_secure_flag" },
	{ _IOC_NR(DEVDRV_GET_SECURE_FLAG),         "npu_ioctl_get_secure_flag" },
	{ _IOC_NR(DEVDRV_EXIT_SHAERE_MEM),         "npu_ioctl_exit_share_mem" },
	{ _IOC_NR(DEVDRV_FLUSH_SMMU_TLB),          "npu_ioctl_flush_smmu_tlb" },
	{ _IOC_NR(DEVDRV_MMAP_DB),                 "npu_ioctl_mmap_db_vaddr" },
	{ _IOC_NR(DEVDRV_UNMAP_DB),                "npu_ioctl_unmap_db_vaddr" },
	{ _IOC_NR(DEVDRV_CUSTOM_IOCTL),            "npu_ioctl_custom" },
};

static npu_custom_cmd_to_name_t s_custom_cmd_func_name_map[] = {
	{ DEVDRV_IOC_VA_TO_PA,                      "npu_ioctl_davinci_va_to_pa" },
	{ DEVDRV_IOC_GET_SVM_SSID,                  "npu_ioctl_get_svm_ssid" },
	{ DEVDRV_IOC_GET_CHIP_INFO,                 "npu_ioctl_get_chip_info" },
	{ DEVDRV_IOC_ALLOC_CONTIGUOUS_MEM,          "npu_ioctl_alloc_cm" },
	{ DEVDRV_IOC_FREE_CONTIGUOUS_MEM,           "npu_ioctl_free_cm" },
	{ DEVDRV_IOC_GET_SHM_MEM_TA_VADDR,          "npu_ioctl_get_shm_ta_vaddr" },
	{ DEVDRV_IOC_MMAP_PHY_MEM_TA_VADDR,         "npu_ioctl_mmap_ta_vaddr" },
	{ DEVDRV_IOC_UNMAP_HIAI_TA_VADDR,           "npu_ioctl_unmap_ta_vaddr" },
	{ DEVDRV_IOC_POWERUP,                       "npu_ioctl_powerup" },
	{ DEVDRV_IOC_POWERDOWN,                     "npu_ioctl_powerdown" },
	{ DEVDRV_IOC_REBOOT,                        "npu_ioctl_reboot" },
};

struct npu_manager_info *npu_get_manager_info(void)
{
	return g_dev_manager_info;
}

static int npu_dev_open(void)
{
	struct npu_dev_ctx* cur_dev_ctx = NULL;
	struct npu_proc_ctx *proc_ctx = NULL;
	struct npu_ts_cq_info *cq_info = NULL;
	const u8 dev_id = 0; // should get from manager info
	int ret;

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	COND_RETURN_ERROR(cur_dev_ctx == NULL, -ENODEV, "cur_dev_ctx %d is null", dev_id);

	NPU_WARN("npu_dev_open start.cur_dev_ctx->accessible=%u",
		atomic_read(&cur_dev_ctx->accessible));

	MUTEX_LOCK(open_close);
	if (atomic_read(&cur_dev_ctx->accessible) == 0) {
		MUTEX_UNLOCK(open_close);
		NPU_ERR("npu dev has already been opened!");
		return -EBUSY;
	}

	proc_ctx = TEE_Malloc(sizeof(struct npu_proc_ctx), 0);
	if(proc_ctx == NULL) {
		MUTEX_UNLOCK(open_close);
		NPU_ERR("alloc memory for proc_ctx failed");
		return -ENOMEM;
	}

	if (memset_s(proc_ctx, sizeof(struct npu_proc_ctx),  0, sizeof(struct npu_proc_ctx)) != EOK) {
		NPU_ERR("memset_s proc_cts failed");
	}
	npu_proc_ctx_init(proc_ctx);
	proc_ctx->devid = cur_dev_ctx->devid;
	npu_set_proc_ctx(proc_ctx);

	// alloc cq for current hiai ta
	MUTEX_LOCK(calc_cq);
	cq_info = npu_proc_alloc_cq(proc_ctx);
	if (cq_info == NULL) {
		MUTEX_UNLOCK(calc_cq);
		NPU_ERR("alloc persistent cq for proc_context failed");
		ret = -ENOMEM;
		goto proc_alloc_cq_failed;
	}
	NPU_DEBUG("alloc persistent cq for proc_context success");
	MUTEX_UNLOCK(calc_cq);

	(void)npu_add_proc_ctx(&proc_ctx->dev_ctx_list, dev_id);  // add proc_ctx to cur dev_ctx proc list
	npu_bind_proc_ctx_with_cq_int_ctx(proc_ctx);	// bind proc_ctx to cq report int ctx
	npu_open_npu_callback_proc(dev_id);	// callback char dev init rs before npu powerup
	atomic_dec(&cur_dev_ctx->accessible);
	MUTEX_UNLOCK(open_close);
	NPU_INFO("npu_open succeed");
	return 0;

proc_alloc_cq_failed:
	MUTEX_UNLOCK(open_close);
	TEE_Free(proc_ctx);
	proc_ctx = NULL;
	return ret;
}

static int npu_dev_release(int fd)
{
	struct npu_proc_ctx *proc_ctx = npu_get_proc_ctx(fd);
	COND_RETURN_ERROR(proc_ctx == NULL, -1, "get proc_ctx fail");

	u8 dev_id = proc_ctx->devid; // should get from manager info
	struct npu_dev_ctx* cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	COND_RETURN_ERROR(cur_dev_ctx == NULL, -1, "cur_dev_ctx %d is null", dev_id);

	NPU_WARN("npu_release start.cur_dev_ctx->accessible=%u",
		atomic_read(&cur_dev_ctx->accessible));

	npu_cma_resource_recycle(cur_dev_ctx);

	// callback char dev release rs before npu powerdown
	npu_release_npu_callback_proc(dev_id);

	MUTEX_LOCK(open_close);
	atomic_inc(&cur_dev_ctx->accessible);

	// resource leak happened
	if (npu_is_proc_resource_leaks(proc_ctx) == true) {
		npu_resource_leak_print(proc_ctx);
		struct npu_platform_info *plat_info = npu_plat_get_info();
		if (plat_info == NULL) {
			NPU_ERR("get plat_ops failed");
			MUTEX_UNLOCK(open_close);
			return -EFAULT;
		}

		npu_recycle_npu_resources(proc_ctx);

		MUTEX_LOCK(pm);
		int ret = npu_powerdown(cur_dev_ctx);
		if (ret) {
			NPU_ERR("npu powerdown failed\n");
		}
		MUTEX_UNLOCK(pm);

		TEE_Free(proc_ctx);
		npu_clear_proc_ctx();
		proc_ctx = NULL;
		MUTEX_UNLOCK(open_close);
		return 0;
	}

	// normal case
	npu_unbind_proc_ctx_with_cq_int_ctx(proc_ctx);
	(void)npu_remove_proc_ctx(&proc_ctx->dev_ctx_list, proc_ctx->devid);

	MUTEX_LOCK(calc_cq);
	(void)npu_proc_free_cq(proc_ctx);
	MUTEX_UNLOCK(calc_cq);

	MUTEX_LOCK(pm);
	int ret = npu_powerdown(cur_dev_ctx);
	if (ret) {
		NPU_ERR("npu powerdown failed\n");
	}
	MUTEX_UNLOCK(pm);

	TEE_Free(proc_ctx);
	npu_clear_proc_ctx();
	proc_ctx = NULL;
	MUTEX_UNLOCK(open_close);

	NPU_INFO("npu_npu_release succeed");
	return ret;
}

char *npu_io_cmd_to_string(unsigned int cmd)
{
	uint16_t idx;
	uint16_t count;

	count = sizeof(s_io_cmd_func_name_map) / sizeof(npu_io_cmd_to_name_t);
	for (idx = 0; idx < count; idx += 1) {
		if (_IOC_NR(cmd) == s_io_cmd_func_name_map[idx].ioc_nr) {
			return s_io_cmd_func_name_map[idx].name;
		}
	}
	return "ERROR_NOT_DEFINE";
}

char *npu_custom_cmd_to_string(unsigned int cmd)
{
	uint16_t idx;
	uint16_t count;

	count = sizeof(s_custom_cmd_func_name_map) / sizeof(npu_io_cmd_to_name_t);
	for (idx = 0; idx < count; idx += 1) {
		if (cmd == s_custom_cmd_func_name_map[idx].cmd) {
			return s_custom_cmd_func_name_map[idx].name;
		}
	}
	return "ERROR_CUSTOM_NOT_DEFINE";
}


static void npu_dev_ioctl_call_init(void)
{
	int i;
	for (i = 0; i < DEVDRV_MAX_CMD; i++) {
		npu_dev_ioctl_call[i] = NULL;
	}

	npu_dev_ioctl_call[_IOC_NR(DEVDRV_ALLOC_STREAM_ID)] =
		npu_ioctl_alloc_stream;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_FREE_STREAM_ID)] =
		npu_ioctl_free_stream;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_GET_OCCUPY_STREAM_ID)] =
		npu_ioctl_get_occupy_stream_id;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_ALLOC_EVENT_ID)] =
		npu_ioctl_alloc_event;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_FREE_EVENT_ID)] =
		npu_ioctl_free_event;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_ALLOC_MODEL_ID)] =
		npu_ioctl_alloc_model;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_FREE_MODEL_ID)] =
		npu_ioctl_free_model;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_ALLOC_TASK_ID)] =
		npu_ioctl_alloc_task;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_FREE_TASK_ID)] =
		npu_ioctl_free_task;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_MAILBOX_SEND)] =
		npu_ioctl_mailbox_send;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_GET_TS_TIMEOUT_ID)] =
		npu_ioctl_get_ts_timeout;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_CUSTOM_IOCTL)] =
		npu_ioctl_custom;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_SET_SECURE_FLAG)] =
		npu_ioctl_set_secure_flag;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_GET_SECURE_FLAG)] =
		npu_ioctl_get_secure_flag;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_EXIT_SHAERE_MEM)] =
		npu_ioctl_exit_share_mem;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_FLUSH_SMMU_TLB)] =
		npu_ioctl_flush_smmu_tlb;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_MMAP_DB)] =
		npu_ioctl_mmap_db_vaddr;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_UNMAP_DB)] =
		npu_ioctl_unmap_db_vaddr;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_MMAP_POWER_STATUS)] =
		npu_ioctl_mmap_power_status_vaddr;
	npu_dev_ioctl_call[_IOC_NR(DEVDRV_UNMAP_POWER_STATUS)] =
		npu_ioctl_unmap_power_status_vaddr;
}

int npu_proc_dev_ioctl_call(struct npu_proc_ctx *proc_ctx, npu_ops_ioctl_info *command_info)
{
	int ret;
	unsigned int cmd;

	if (command_info == NULL) {
		NPU_ERR(" input command_info is NULL\n");
		return -1;
	}
	cmd = command_info->cmd;

	if (cmd < _IO(DEVDRV_ID_MAGIC, 1) || cmd >= _IO(DEVDRV_ID_MAGIC, DEVDRV_MAX_CMD)) {
		NPU_ERR("parameter, arg = 0x%lx, cmd = %d\n", command_info->param, cmd);
		return -1;
	}

	NPU_DEBUG("IOC_NR = %d  cmd = %d func_name = %s\n", _IOC_NR(cmd), cmd, npu_io_cmd_to_string(cmd));

	if (npu_dev_ioctl_call[_IOC_NR(cmd)] == NULL) {
		NPU_ERR("npu_proc_npu_ioctl_call invalid cmd = %d\n", cmd);
		return -1;
	}

	// process ioctl
	ret = npu_dev_ioctl_call[_IOC_NR(cmd)](proc_ctx, (unsigned long)command_info->param,
			(unsigned long)command_info->param_size);
	if (ret != 0) {
		NPU_ERR("process failed, arg = %d\n", cmd);
		return -1;
	}

	return ret;
}

static int npu_manager_init(void)
{
	const u8 dev_id = 0;
	int ret;
	struct npu_platform_info *plat_info = NULL;

	NPU_DEBUG("npu dev %d drv_manager_init start", dev_id);

	if (npu_plat_sec_enable_status() != NPU_SEC_FEATURE_SUPPORTED)
		return -EINVAL;

	ret = npu_platform_probe();
	if (ret) {
		NPU_ERR("probe failed, ret = %d", ret);
		return ret;
	}

	plat_info = npu_plat_get_info();
	if (plat_info == NULL) {
		NPU_ERR("npu_plat_get_info failed");
		return -ENODEV;
	}

	g_dev_manager_info = TEE_Malloc(sizeof(struct npu_manager_info), 0);
	if(g_dev_manager_info == NULL){
		NPU_ERR("TEE_Malloc npu g_dev_manager_info failed");
		return -ENOMEM;
	}

	g_dev_manager_info->plat_info = DEVDRV_MANAGER_DEVICE_ENV;

	npu_dev_ioctl_call_init();
	// init npu powerup or powerdown register info
	npu_register_callbak_info_init();

	// npu device resoure init
	ret = npu_devinit(dev_id);
	if (ret != 0) {
		NPU_ERR("npu dev %d npu_devinit failed", dev_id);
		ret = -ENODEV;
		goto npu_devinit_failed;
	}

	ret = npu_request_cq_report_irq_bh();
	if (ret != 0) {
		NPU_ERR("npu_request_cq_report_irq_bh failed");
		goto request_cq_report_irq_failed;
	}

	// create at init and keep alive all the time
	ret = npu_create_named_sem();
	if (ret) {
		NPU_ERR("npu create named sem failed");
		ret = -ENODEV;
		goto npu_create_named_sem_failed;
	}

	NPU_DEBUG("npu_manager_init success");
	return ret;

npu_create_named_sem_failed:
request_cq_report_irq_failed:
npu_devinit_failed:
	TEE_Free(g_dev_manager_info);
	g_dev_manager_info = NULL;
	NPU_ERR("npu npu_manager_init failed\n");
	return ret;
}

unsigned int npu_dev_sys_call_ioctl(npu_ops_ioctl_info *command_info)
{
	int ret;

	if (command_info == NULL) {
		NPU_ERR(" input command_info is NULL, FATAL arg and ignore\n");
		return 1;
	}

	ret = npu_dev_ioctl(command_info);

	return ret;
}

unsigned int npu_dev_sys_call_open(void)
{
	int ret;
	unsigned int fd = NPU_DEV_SEC_MODE_OPENFD;

	ret = npu_dev_open();
	if (ret) {
		NPU_ERR("npu_dev_open failed ret = %d ", ret);
		return 0;
	}

	return fd; // return for HIAI ta
}

unsigned int npu_dev_sys_call_release(npu_ops_release_info *command_info)
{
	int ret;

	if (command_info == NULL) {
		NPU_ERR(" input command_info is NULL, FATAL arg and ignore\n");
		return 1;
	}

	if (command_info->fd != NPU_DEV_SEC_MODE_OPENFD) {
		NPU_ERR("input err fd:0x%x\n", command_info->fd);
		return 1;
	}

	ret = npu_dev_release(command_info->fd);

	return ret;
}

// temporarily remap custom para struct itself and it internal ptr struct to
// plat_drv vaddr for the purpose of (access) read or write it on plat drv TA
#define npu_remap_custom_para_drv_vaddr(custom_para) \
{ \
	ACCESS_CHECK(custom_para, sizeof(npu_custom_para_t)); \
	ACCESS_WRITE_RIGHT_CHECK(custom_para, sizeof(npu_custom_para_t)); \
	NPU_DEBUG("custom_para,cmd_func = %s cmd = %d arg_size = %d", \
		npu_custom_cmd_to_string(((npu_custom_para_t *)(custom_para))->cmd), \
		((npu_custom_para_t *)(custom_para))->cmd, \
		((npu_custom_para_t *)(custom_para))->arg_size); \
	if (((npu_custom_para_t *)(custom_para))->arg_size > 0) { \
		ACCESS_CHECK(((npu_custom_para_t *)(custom_para))->arg, ((npu_custom_para_t *)(custom_para))->arg_size); \
		ACCESS_WRITE_RIGHT_CHECK(((npu_custom_para_t *)(custom_para))->arg, \
		((npu_custom_para_t *)(custom_para))->arg_size); \
	} \
}

int npu_dev_sys_call(int swi_id, struct drv_param *params, uint64_t permissions)
{
	UINT32 uwRet;
	/* According to ARM AAPCS arguments from 5-> in a function call
	* are stored on the stack, which in this case is pointer by
	* user sp. Our own TrustedCore also push FP and LR on the stack
	* just before SWI, so skip them */
	if (params == NULL || params->args == 0)
		return -1;
	uint64_t *args = (uint64_t *)(uintptr_t)params->args;
	unsigned int param_size; // indicate param mem size
	unsigned int cmd_id;
	npu_ops_ioctl_info *ioctl_cmd_info = NULL;

	if (npu_plat_sec_enable_status() != NPU_SEC_FEATURE_SUPPORTED)
		return -EINVAL;

	HANDLE_SYSCALL(swi_id) {
		SYSCALL_PERMISSION(SW_SYSCALL_NPU_IOCTL_CFG, permissions, AI_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[0], sizeof(npu_ops_ioctl_info));
		if (args[0] == 0) {
			args[0] = OS_ERROR;
			return -1;
		}
		ioctl_cmd_info = (npu_ops_ioctl_info *)(uintptr_t)args[0];
		ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(npu_ops_ioctl_info));
		cmd_id = ioctl_cmd_info->cmd;
		param_size = ioctl_cmd_info->param_size;
		if (((npu_ops_ioctl_info *)(uintptr_t)args[0])->param == NULL || param_size == 0) {
			args[0] = OS_ERROR;
			return -1;
		}

		if (cmd_id == DEVDRV_CUSTOM_IOCTL) {
			npu_remap_custom_para_drv_vaddr(((npu_ops_ioctl_info *)(uintptr_t)args[0])->param);
		} else {
			ACCESS_CHECK_A64(((npu_ops_ioctl_info *)(uintptr_t)args[0])->param, param_size);
			ACCESS_WRITE_RIGHT_CHECK(((npu_ops_ioctl_info *)(uintptr_t)args[0])->param, param_size);
		}
		uwRet = (UINT32)npu_dev_sys_call_ioctl((npu_ops_ioctl_info *)(uintptr_t)args[0]);
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_NPU_OPEN_MODE_CFG, permissions, AI_GROUP_PERMISSION)
		uwRet = (UINT32)npu_dev_sys_call_open();
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_NPU_REALEASE_MODE_CFG, permissions, AI_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[0], sizeof(npu_ops_release_info));
		ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(npu_ops_release_info));
		uwRet = (UINT32)npu_dev_sys_call_release((npu_ops_release_info *)(uintptr_t)args[0]);
		args[0] = uwRet;
		SYSCALL_END
	default:
		return -1;
	}
	return 0;
}

DECLARE_TC_DRV(
	npu_manager,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	npu_manager_init,
	NULL,
	npu_dev_sys_call,
	NULL,
	NULL
);
