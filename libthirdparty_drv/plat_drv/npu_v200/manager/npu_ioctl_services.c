#include <errno.h>
#include "npu_base_define.h"
#include "sre_syscalls_ext.h"
#include "svm.h"
#include "secmem.h"
#include "sec_smmu_com.h"
#include "npu_log.h"
#include "npu_io_cmd_share.h"
#include "npu_ioctl_services.h"
#include "npu_custom_info_share.h"
#include "npu_custom_ioctl_services.h"
#include "npu_platform_resource.h"
#include "npu_platform_register.h"
#include "npu_schedule_task.h"
#include "npu_reg.h"

static int (*g_npu_ioctl_call[NPU_MAX_CMD])(npu_proc_ctx_t *proc_ctx, uintptr_t arg) = {NULL};

static int npu_ioctl_alloc_task(struct npu_proc_ctx *proc_ctx, uintptr_t arg)
{
	npu_task_info_t *task_info = NULL;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;

	NPU_DRV_DEBUG("npu_ioctl_alloc_task begin\n");
	task_info = npu_alloc_task_info(&(dev_ctx->task_mngr));
	if (task_info == NULL) {
		NPU_DRV_ERR("npu alloc task failed\n");
		return -EFAULT;
	}

	task_info->proc_ctx = proc_ctx;
	list_add(&(task_info->list_node), &(proc_ctx->task_list));

	*((int *)arg) =  task_info->task_id;
	NPU_DRV_DEBUG("npu_ioctl_alloc_task end\n");

	return 0;
}

static int npu_ioctl_free_task(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	int task_id = *(int *)arg;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;

	NPU_DRV_DEBUG("npu_ioctl_free_task begin\n");
	npu_task_info_t *task_info = npu_get_task_info(&(dev_ctx->task_mngr), task_id);
	if (task_info == NULL) {
		NPU_DRV_ERR("task id %d is invalid\n", task_id);
		return -EINVAL;
	}

	task_info->proc_ctx = NULL;
	list_del(&(task_info->list_node));
	npu_free_task_info(&(dev_ctx->task_mngr), task_id);
	NPU_DRV_DEBUG("npu_ioctl_free_task end\n");

	return 0;
}

static int npu_ioctl_alloc_stream(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	npu_stream_alloc_info_t *para = (npu_stream_alloc_info_t *)arg;
	npu_stream_info_t* stream_info = NULL;
	npu_dev_ctx_t *dev_ctx = NULL;

	NPU_DRV_DEBUG("npu_ioctl_alloc_stream begin, para->strategy=%d", para->strategy);
	dev_ctx = proc_ctx->dev_ctx;
	stream_info = npu_alloc_stream_info(&(dev_ctx->stream_mngr), para->strategy);
	if (stream_info == NULL) {
		NPU_DRV_ERR("npu_alloc_stream failed");
		return -ENOKEY;
	}

	stream_info->proc_ctx = proc_ctx;
	stream_info->priority = para->priority;
	list_add(&(stream_info->list_node), &(proc_ctx->stream_list));

	para->stream_id = stream_info->stream_id;
	NPU_DRV_DEBUG("npu_ioctl_alloc_stream end, para->stream_id=%d", para->stream_id);

	return 0;
}

static int npu_ioctl_free_stream(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	int stream_id = *(int *)arg;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;

	NPU_DRV_DEBUG("npu_ioctl_free_stream begin\n");
	npu_stream_info_t *stream_info = npu_get_stream_info(&(dev_ctx->stream_mngr), stream_id);
	if (stream_info == NULL) {
		NPU_DRV_ERR("stream id %d is invalid\n", stream_id);
		return -EINVAL;
	}

	stream_info->proc_ctx = NULL;
	list_del(&(stream_info->list_node));
	npu_free_stream_info(&(dev_ctx->stream_mngr), stream_id);
	NPU_DRV_DEBUG("npu_ioctl_free_stream end\n");

	return 0;
}

static int npu_ioctl_alloc_model(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	npu_model_info_t *model_info = NULL;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;

	NPU_DRV_DEBUG("npu_ioctl_alloc_model begin\n");
	model_info = npu_alloc_model_info(&(dev_ctx->model_mngr));
	if (model_info == NULL) {
		NPU_DRV_ERR("npu_ioctl_alloc_model failed\n");
		return -ENOKEY;
	}

	model_info->proc_ctx = proc_ctx;
	list_add(&(model_info->list_node), &(proc_ctx->model_list));
	*((int *)arg) =  model_info->model_id;
	NPU_DRV_DEBUG("npu_ioctl_alloc_model end\n");

	return 0;
}

static int npu_ioctl_free_model(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	int model_id = *(int *)arg;

	struct list_head *n = NULL;
	struct list_head *pos = NULL;
	npu_stream_info_t *stream_info = NULL;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;

	NPU_DRV_DEBUG("npu_ioctl_free_model begin\n");
	npu_model_info_t *model_info = npu_get_model_info(&(dev_ctx->model_mngr), model_id);
	if (model_info == NULL) {
		NPU_DRV_ERR("model id %d is invalid\n", model_id);
		return -EINVAL;
	}

	list_for_each_safe(pos, n, &(model_info->stream_list)) {
		stream_info = list_entry(pos, npu_stream_info_t, list_node);

		/* move stream from model to proc */
		list_del(pos);
		list_add(&(stream_info->list_node), &(proc_ctx->stream_list));
	}

	model_info->proc_ctx = NULL;
	list_del(&(model_info->list_node));
	npu_free_model_info(&(dev_ctx->model_mngr), model_id);
	NPU_DRV_DEBUG("npu_ioctl_free_model end\n");

	return 0;
}

static int npu_ioctl_alloc_event(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	npu_event_info_t *event_info = NULL;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;

	NPU_DRV_DEBUG("npu_ioctl_alloc_event begin\n");
	event_info = npu_alloc_event_info(&(dev_ctx->event_mngr));
	if (event_info == NULL) {
		NPU_DRV_ERR("npu_ioctl_alloc_event failed\n");
		return -ENOKEY;
	}

	event_info->proc_ctx = proc_ctx;
	list_add(&(event_info->list_node), &(proc_ctx->event_list));
	*((int *)arg) =  event_info->event_id;
	NPU_DRV_DEBUG("npu_ioctl_alloc_event end\n");

	return 0;
}

static int npu_ioctl_free_event(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	int event_id = *(int *)arg;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;

	NPU_DRV_DEBUG("npu_ioctl_free_event begin\n");
	npu_event_info_t *event_info = npu_get_event_info(&(dev_ctx->event_mngr), event_id);
	if (event_info == NULL) {
		NPU_DRV_ERR("event id %d is invalid\n", event_id);
		return -EINVAL;
	}

	event_info->proc_ctx = NULL;
	list_del(&(event_info->list_node));
	npu_free_event_info(&(dev_ctx->event_mngr), event_id);
	NPU_DRV_DEBUG("npu_ioctl_free_event end\n");

	return 0;
}

static int npu_ioctl_send_request(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	npu_schedule_comm_sqe_t *sch_task = (npu_schedule_comm_sqe_t *)arg;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;

	return npu_schedule_task(dev_ctx, sch_task);
}

static int npu_ioctl_flush_smmu_tlb(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	UNUSED(arg);

	int ret;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;
	struct sec_smmu_para *svm_param = &(dev_ctx->smmu_para);
	uint32_t power_status = npu_pm_query_power_status();

	NPU_DRV_DEBUG("npu_ioctl_flush_smmu_tlb begin\n");
	if ((dev_ctx->power_stage != DEVDRV_PM_UP) || (power_status != DRV_NPU_POWER_ON_SEC_FLAG)) {
		NPU_DRV_ERR("wrong status: power_stage=%d, power_status=%d ! can`t flush smmu tlb\n", dev_ctx->power_stage, power_status);
		return -EFAULT;
	}

    ret = __teesvm_ioctl(SVM_SEC_CMD_FLUSH_TLB, svm_param);

	if (ret != 0)
		NPU_DRV_ERR("tee npu flush tlb failed, ret = %d", ret);

	NPU_DRV_DEBUG("npu_ioctl_flush_smmu_tlb end\n");

	return 0;
}

static int npu_ioctl_get_dev_info(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	UNUSED(proc_ctx);
	npu_device_info_t *para = (npu_device_info_t *)arg;

	para->envType = DEVDRV_PLAT_TYPE_ASIC;
	para->ctrl_cpu_ip = 0;
	para->ctrl_cpu_id = DEVDRV_CTRL_CPU_ID;
	para->ctrl_cpu_core_num = 1;
	para->ctrl_cpu_endian_little = 1;
	para->tscpu_core_num = 1;
	para->aicpu_core_num = DEVDRV_PLAT_AICPU_MAX;
	para->aicore_num = DEVDRV_PLAT_AICORE_MAX;
	para->aicpu_core_id = 0;
	para->aicore_id = 0;
	para->aicpu_occupy_bitmap = 0;

	return 0;
}

static int npu_ioctl_get_sch_result(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	UNUSED(proc_ctx);
	UNUSED(arg);

	return npu_hwts_get_sch_result();
}

void npu_init_ioctl_call(void)
{
	npu_init_custom_ioctl_call();

	g_npu_ioctl_call[_IOC_NR(DEVDRV_ALLOC_STREAM_ID)] = npu_ioctl_alloc_stream;
	g_npu_ioctl_call[_IOC_NR(DEVDRV_FREE_STREAM_ID)] = npu_ioctl_free_stream;
	g_npu_ioctl_call[_IOC_NR(DEVDRV_ALLOC_EVENT_ID)] = npu_ioctl_alloc_event;
	g_npu_ioctl_call[_IOC_NR(DEVDRV_FREE_EVENT_ID)] = npu_ioctl_free_event;
	g_npu_ioctl_call[_IOC_NR(DEVDRV_ALLOC_MODEL_ID)] = npu_ioctl_alloc_model;
	g_npu_ioctl_call[_IOC_NR(DEVDRV_FREE_MODEL_ID)] = npu_ioctl_free_model;
	g_npu_ioctl_call[_IOC_NR(DEVDRV_REQUEST_SEND)] = npu_ioctl_send_request;
	g_npu_ioctl_call[_IOC_NR(DEVDRV_ALLOC_TASK_ID)] = npu_ioctl_alloc_task;
	g_npu_ioctl_call[_IOC_NR(DEVDRV_FREE_TASK_ID)] = npu_ioctl_free_task;
	g_npu_ioctl_call[_IOC_NR(DEVDRV_CUSTOM_IOCTL)] = npu_ioctl_custom;
	g_npu_ioctl_call[_IOC_NR(DEVDRV_FLUSH_SMMU_TLB)] = npu_ioctl_flush_smmu_tlb;
	g_npu_ioctl_call[_IOC_NR(DEVDRV_GET_DEV_INFO)] = npu_ioctl_get_dev_info;
	g_npu_ioctl_call[_IOC_NR(DEVDRV_GET_SCH_RESULT)] = npu_ioctl_get_sch_result;
}

int npu_proc_ioctl_call(npu_proc_ctx_t *proc_ctx, unsigned int cmd, uintptr_t arg)
{
	int ret;

	if (cmd < _IO(DEVDRV_ID_MAGIC, 1) || cmd >= _IO(DEVDRV_ID_MAGIC, NPU_MAX_CMD)) {
		NPU_DRV_ERR("parameter, arg = 0x%lx, cmd = %u\n", arg, cmd);
		return -EINVAL;
	}

	NPU_DRV_DEBUG("IOC_NR = %d cmd = %d\n", _IOC_NR(cmd), cmd);

	if (g_npu_ioctl_call[_IOC_NR(cmd)] == NULL) {
		NPU_DRV_ERR("devdrv_proc_npu_ioctl_call invalid cmd = %u\n", cmd);
		return -EINVAL;
	}

	// process ioctl
	ret = g_npu_ioctl_call[_IOC_NR(cmd)](proc_ctx, arg);
	if (ret != 0) {
		NPU_DRV_ERR("process failed, cmd = %u\n", cmd);
		return -EINVAL;
	}

	return ret;
}

