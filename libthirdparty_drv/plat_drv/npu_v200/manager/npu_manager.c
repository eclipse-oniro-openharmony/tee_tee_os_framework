#include <errno.h>
#include <string.h>
#include <hm_unistd.h>

#include "sre_syscalls_id_ext.h"
#include "sre_access_control.h"
#include "tee_mem_mgmt_api.h"
#include "sre_syscalls_id.h"
#include "sre_dev_relcb.h"
#include "drv_pal.h"
#include "drv_module.h"
#include <hmdrv_stub.h>

#include "npu_log.h"
#include "npu_dev_ctx_mngr.h"
#include "npu_proc_ctx_mngr.h"
#include "npu_schedule_task.h"
#include "npu_io_cmd_share.h"
#include "npu_custom_info_share.h"
#include "npu_ioctl_services.h"
#include "npu_semaphore.h"

static int npu_proc_recycle_cb(void *data);

static int npu_dev_open(u8 dev_id)
{
	npu_dev_ctx_t *dev_ctx = NULL;
	npu_proc_ctx_t *proc_ctx = NULL;
	NPU_DRV_INFO("npu_dev_open start");

	dev_ctx = npu_get_dev_ctx(dev_id);
	COND_RETURN_ERROR(dev_ctx == NULL, -ENODEV, "dev_ctx %d is null", dev_id);

	proc_ctx = npu_create_proc_ctx(dev_ctx);
	COND_RETURN_ERROR(proc_ctx == NULL, -ENODEV, "proc_ctx %d is null", dev_id);

	int ret = SRE_TaskRegister_DevRelCb((DEV_RELEASE_CALLBACK)npu_proc_recycle_cb, (void *)(uintptr_t)dev_id);
	if (ret)
		NPU_DRV_WARN("npu_dev_open SRE_TaskRegister_DevRelCb error:%d", ret);

	NPU_DRV_DEBUG("devdrv_open succeed\n");
	return 0;
}

static int npu_dev_release(u8 dev_id)
{
	npu_dev_ctx_t *dev_ctx = NULL;
	npu_proc_ctx_t *proc_ctx = NULL;
	NPU_DRV_INFO("npu_release start, dev_id = %u", dev_id);

	dev_ctx = npu_get_dev_ctx(dev_id);
	COND_RETURN_ERROR(dev_ctx == NULL, -EINVAL, "get dev_ctx fail");

	proc_ctx = npu_get_proc_ctx(dev_ctx);
	COND_RETURN_ERROR(proc_ctx == NULL, -EINVAL, "get proc_ctx fail");

	npu_destroy_proc_ctx(proc_ctx);

	(void)SRE_TaskUnRegister_DevRelCb((DEV_RELEASE_CALLBACK)npu_proc_recycle_cb, (void *)(uintptr_t)dev_id);
	NPU_DRV_INFO("npu_npu_release succeed");
	return 0;
}

static int npu_proc_recycle_cb(void *data)
{
	npu_dev_ctx_t *dev_ctx = NULL;
	npu_proc_ctx_t *proc_ctx = NULL;
	const u8 dev_id = (u8)(uintptr_t)data;

	dev_ctx = npu_get_dev_ctx(dev_id);
	COND_RETURN_ERROR(dev_ctx == NULL, -EINVAL, "get dev_ctx fail");

	proc_ctx = npu_get_proc_ctx(dev_ctx);
	COND_RETURN_ERROR(proc_ctx == NULL, -EINVAL, "get proc_ctx fail");

	npu_deinit_proc_ctx(proc_ctx);
	return 0;
}

static inline int npu_check_ioctl_info(npu_ops_ioctl_info_t *command_info)
{
	if (command_info == NULL) {
		NPU_DRV_ERR("npu_check_ioctl_info command_info is NULL\n");
		return -1;
	}

	if (command_info->param == NULL) {
		NPU_DRV_ERR("npu_check_ioctl_info command_info param is NULL\n");
		return -1;
	}

	if (command_info->fd != NPU_DEV_SEC_MODE_OPENFD) {
		NPU_DRV_ERR("npu_check_ioctl_info command_info fd is invalid, %d\n", command_info->fd);
		return -1;
	}

	return 0;
}

static inline int npu_dev_ioctl(u8 dev_id, unsigned int cmd, uintptr_t arg)
{
	int ret;
	npu_dev_ctx_t *dev_ctx = NULL;
	npu_proc_ctx_t *proc_ctx = NULL;

	dev_ctx = npu_get_dev_ctx(dev_id);
	COND_RETURN_ERROR(dev_ctx == NULL, -EINVAL, "get dev_ctx fail");

	proc_ctx = npu_get_proc_ctx(dev_ctx);
	COND_RETURN_ERROR(proc_ctx == NULL, -EINVAL, "get proc_ctx fail");

	ret = npu_proc_ioctl_call(proc_ctx, cmd, arg);
	COND_RETURN_ERROR(ret != 0, -1, "npu_npu_ioctl process failed,arg=%lu, cmd = %u\n", arg, cmd);

	return 0;
}

static inline int npu_dev_sys_call_ioctl(npu_ops_ioctl_info_t *command_info)
{
	const u8 dev_id = 0;
	if (npu_check_ioctl_info(command_info) != 0)
		return 1;

	return npu_dev_ioctl(dev_id, command_info->cmd, (uintptr_t)command_info->param);
}

static inline unsigned int npu_dev_sys_call_open(void)
{
	int ret;
	const u8 dev_id = 0;
	unsigned int fd = NPU_DEV_SEC_MODE_OPENFD;

	ret = npu_dev_open(dev_id);
	if (ret != 0) {
		NPU_DRV_ERR("npu_dev_open failed ret = %d", ret);
		return 0;
	}

	return fd;
}

static inline unsigned int npu_dev_sys_call_release(npu_ops_release_info_t *command_info)
{
	const u8 dev_id = 0;

	if (command_info == NULL) {
		NPU_DRV_ERR(" input command_info is NULL, FATAL arg and ignore\n");
		return 1;
	}

	if (command_info->fd != NPU_DEV_SEC_MODE_OPENFD) {
		NPU_DRV_ERR("input err fd:0x%x\n", command_info->fd);
		return 1;
	}

	return npu_dev_release(dev_id);
}

// temporarily remap custom para struct itself and it internal ptr struct to
// plat_drv vaddr for the purpose of (access) read or write it on plat drv TA
#define npu_remap_custom_para_drv_vaddr(custom_para) \
do { \
	ACCESS_CHECK_A64(custom_para, sizeof(npu_custom_para_t)); \
	ACCESS_WRITE_RIGHT_CHECK(custom_para, sizeof(npu_custom_para_t)); \
	NPU_DRV_DEBUG("custom_para, cmd = %d arg_size = %d", \
		((npu_custom_para_t *)(custom_para))->cmd, \
		((npu_custom_para_t *)(custom_para))->arg_size); \
	if (((npu_custom_para_t *)(custom_para))->arg_size > 0) { \
		ACCESS_CHECK_A64(((npu_custom_para_t *)(custom_para))->arg, ((npu_custom_para_t *)(custom_para))->arg_size); \
		ACCESS_WRITE_RIGHT_CHECK(((npu_custom_para_t *)(custom_para))->arg, \
		((npu_custom_para_t *)(custom_para))->arg_size); \
		if (((npu_custom_para_t *)(custom_para))->cmd == DEVDRV_IOC_LOAD_MODEL_BUFF) { \
			npu_model_desc_t *desc = (npu_model_desc_t *)(uintptr_t)(((npu_custom_para_t *)(custom_para))->arg); \
			for (int idx = 0; idx < NPU_MODEL_STREAM_NUM && idx < desc->stream_cnt; idx++) { \
				NPU_DRV_DEBUG("old desc->stream_addr[%d]=%p, stream_tasks=%u", idx, desc->stream_addr[idx], \
					desc->stream_tasks[idx]); \
				ACCESS_CHECK_A64(desc->stream_addr[idx], desc->stream_tasks[idx] * NPU_RT_TASK_SIZE); \
				ACCESS_WRITE_RIGHT_CHECK(desc->stream_addr[idx], desc->stream_tasks[idx] * NPU_RT_TASK_SIZE); \
				NPU_DRV_DEBUG("new desc->stream_addr[%d]=%p, stream_tasks=%u", idx, desc->stream_addr[idx], \
					desc->stream_tasks[idx]); \
			} \
		} \
	} \
} while(0);

static int npu_dev_sys_call(int swi_id, struct drv_param *params, uint64_t permissions)
{
	/* According to ARM AAPCS arguments from 5-> in a function call
	* are stored on the stack, which in this case is pointer by
	* user sp. Our own TrustedCore also push FP and LR on the stack
	* just before SWI, so skip them */
	uint64_t *args = (uint64_t *)(uintptr_t)params->args;
	npu_ops_ioctl_info_t *ioctl_cmd_info = NULL;
	unsigned int param_size;
	unsigned int cmd_id;
	UINT32 uwRet;

	if (npu_sec_enable() != NPU_SEC_FEATURE_SUPPORTED) {
		NPU_DRV_WARN("this platform unsupport secure workmode");
		return -1;
	}

	HANDLE_SYSCALL(swi_id) {
		SYSCALL_PERMISSION(SW_SYSCALL_NPU_IOCTL_CFG, permissions, AI_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[0], sizeof(npu_ops_ioctl_info_t));
		if (args[0] == 0) {
			args[0] = OS_ERROR;
			return -1;
		}

		ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(npu_ops_ioctl_info_t));
		ioctl_cmd_info = (npu_ops_ioctl_info_t *)(uintptr_t)args[0];
		cmd_id = ioctl_cmd_info->cmd;
		param_size = ioctl_cmd_info->param_size;
		if (cmd_id == DEVDRV_CUSTOM_IOCTL) {
			npu_remap_custom_para_drv_vaddr(((npu_ops_ioctl_info_t *)(uintptr_t)args[0])->param);
		} else {
			ACCESS_CHECK_A64(((npu_ops_ioctl_info_t *)(uintptr_t)args[0])->param, param_size);
			ACCESS_WRITE_RIGHT_CHECK(((npu_ops_ioctl_info_t *)(uintptr_t)args[0])->param, param_size);
		}
		uwRet = (UINT32)npu_dev_sys_call_ioctl((npu_ops_ioctl_info_t *)(uintptr_t)args[0]);
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_NPU_OPEN_MODE_CFG, permissions, AI_GROUP_PERMISSION)
		uwRet = (UINT32)npu_dev_sys_call_open();
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_NPU_REALEASE_MODE_CFG, permissions, AI_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[0], sizeof(npu_ops_release_info_t));
		ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(npu_ops_release_info_t));
		uwRet = (UINT32)npu_dev_sys_call_release((npu_ops_release_info_t *)(uintptr_t)args[0]);
		args[0] = uwRet;
		SYSCALL_END
	default:
		return -1;
	}
	return 0;
}

static int npu_manager_init(void)
{
	int ret;
	const u8 dev_id = 0;

	NPU_DRV_DEBUG("npu dev %d drv_manager_init start", dev_id);
	ret = npu_init_dev_ctx(dev_id);
	if (ret != 0) {
		NPU_DRV_ERR("dev %u init failed, ret = %d", dev_id, ret);
		return ret;
	}

	npu_init_ioctl_call();

	ret = npu_create_named_sem();
	if (ret) {
		NPU_DRV_ERR("npu create named sem failed");
		return ret;
	}

	NPU_DRV_DEBUG("npu_manager_init success");
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
