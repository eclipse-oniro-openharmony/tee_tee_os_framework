#include <errno.h>
#include "npu_custom_ioctl_services.h"
#include "npu_custom_info_share.h"
#include "npu_hwts_sqe.h"
#include "npu_log.h"
#include "npu_pm.h"
#include "secmem.h"
#include "sec_smmu_com.h"

static int (*g_npu_custom_ioctl_call[DEVDRV_IOC_CUSTOM_MAX])(npu_proc_ctx_t *proc_ctx, uintptr_t arg) = {NULL};

static int npu_ioctl_get_svm_ssid(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	npu_dev_ctx_t *dev_ctx = NULL;
	npu_process_info_t *info_p = NULL;
	struct sec_smmu_para *svm_param = NULL;

	dev_ctx = proc_ctx->dev_ctx;
	svm_param = &(dev_ctx->smmu_para);
    info_p = (npu_process_info_t *)arg;

	info_p->ttbr = svm_param->ttbr;
	info_p->tcr = svm_param->tcr;
	info_p->pasid = svm_param->ssid;

	NPU_DRV_DEBUG("get ssid %p ttbr %p tcr %p arg_size = %p \n",
	         (void *)info_p->pasid, (void *)(uintptr_t)info_p->ttbr,
	         (void *)(uintptr_t)info_p->tcr, (void *)sizeof(struct npu_process_info));
	return 0;
}

static int npu_ioctl_powerup(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	int ret;
	u32 secure_mode;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;
	npu_secure_info_t *sec_info = (npu_secure_info_t *)arg;

	secure_mode = sec_info->secure_mode;
	NPU_DRV_WARN("power up secure_mode = 0x%x \n", secure_mode);

	if (secure_mode != NPU_SEC) {
		NPU_DRV_ERR("illgal secure mode\n");
		return -1;
	}

	ret = npu_powerup(dev_ctx);
	if (ret != 0) {
		NPU_DRV_ERR("npu powerup failed\n");
		return ret;
	}

	return ret;
}

static int npu_ioctl_powerdown(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	int ret;
	npu_secure_info_t *sec_info = (npu_secure_info_t *)arg;
	u32 secure_mode = sec_info->secure_mode;
	if (secure_mode != NPU_SEC) {
		NPU_DRV_ERR("illgal secure mode\n");
		return -1;
	}

	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;
	ret = npu_powerdown(dev_ctx);
	if (ret != 0) {
		NPU_DRV_ERR("npu powerdown failed\n");
		return ret;
	}

	NPU_DRV_WARN("npu_ioctl_powerdown succ\n");
	return ret;
}

static int npu_ioctl_load_model(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	int ret;
	u16 idx, sqe_count;
	npu_model_info_t *model_info = NULL;
	npu_stream_info_t *stream_info = NULL;
	npu_sink_stream_sub_t *sink_sub = NULL;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;
	npu_model_desc_t *model_desc = (npu_model_desc_t *)arg;

	NPU_DRV_DEBUG("npu_ioctl_load_model enter, model_id= %u, stream_cnt= %u\n",
		model_desc->model_id, model_desc->stream_cnt);

	COND_RETURN_ERROR(model_desc->stream_cnt > NPU_MODEL_STREAM_NUM,
		-1, "stream_cnt = %u, invalid\n", model_desc->stream_cnt);

	model_info = npu_get_model_info(&(dev_ctx->model_mngr), model_desc->model_id);
	COND_RETURN_ERROR(model_info == NULL, -1, "model id = %u, invalid\n", model_desc->model_id);

	for (idx = 0; idx < model_desc->stream_cnt; idx++) {
		sqe_count = model_desc->stream_tasks[idx];
		COND_RETURN_ERROR(sqe_count > NPU_MAX_HWTS_SQ_DEPTH, -1, "task count = %u, invalid\n", sqe_count);

		stream_info = npu_get_stream_info(&(dev_ctx->stream_mngr), model_desc->stream_id[idx]);
		COND_RETURN_ERROR(stream_info == NULL, -1, "stream id = %u, invalid\n", model_desc->stream_id[idx]);

		sink_sub = stream_info->sink_sub;
		COND_RETURN_ERROR(sink_sub == NULL, -1, "no sink, stream id = %u, invalid\n", model_desc->stream_id[idx]);

		/* save hwts_sqe */
		ret = npu_format_hwts_sqe((void *)sink_sub->virt_addr, model_desc->stream_addr[idx], sqe_count);
		COND_RETURN_ERROR(ret != 0, -1, "format fail, stream id = %u, invalid\n", model_desc->stream_id[idx]);

		sink_sub->sqe_count = sqe_count;

		/* move stream from proc to model */
		list_del(&(stream_info->list_node));
		list_add(&(stream_info->list_node), &(model_info->stream_list));
	}

	NPU_DRV_DEBUG("npu_ioctl_load_model end\n");
	return 0;
}

void npu_init_custom_ioctl_call(void)
{
	g_npu_custom_ioctl_call[DEVDRV_IOC_VA_TO_PA] = NULL;
	g_npu_custom_ioctl_call[DEVDRV_IOC_GET_SVM_SSID] = npu_ioctl_get_svm_ssid;
	g_npu_custom_ioctl_call[DEVDRV_IOC_GET_CHIP_INFO] = NULL;
	g_npu_custom_ioctl_call[DEVDRV_IOC_ALLOC_CONTIGUOUS_MEM] = NULL;
	g_npu_custom_ioctl_call[DEVDRV_IOC_FREE_CONTIGUOUS_MEM] = NULL;
	g_npu_custom_ioctl_call[DEVDRV_IOC_GET_SHM_MEM_TA_VADDR] = NULL;
	g_npu_custom_ioctl_call[DEVDRV_IOC_MMAP_PHY_MEM_TA_VADDR] = NULL;
	g_npu_custom_ioctl_call[DEVDRV_IOC_UNMAP_TA_VADDR] = NULL;
	g_npu_custom_ioctl_call[DEVDRV_IOC_POWERUP] = npu_ioctl_powerup;
	g_npu_custom_ioctl_call[DEVDRV_IOC_POWERDOWN] = npu_ioctl_powerdown;
	g_npu_custom_ioctl_call[DEVDRV_IOC_REBOOT] = NULL;
	g_npu_custom_ioctl_call[DEVDRV_IOC_LOAD_MODEL_BUFF] = npu_ioctl_load_model;
}

int npu_ioctl_custom(npu_proc_ctx_t *proc_ctx, uintptr_t arg)
{
	int ret;
	npu_custom_para_t *custom_param = (npu_custom_para_t *)arg;

	if ((custom_param->cmd >= DEVDRV_IOC_CUSTOM_MAX) ||
		(g_npu_custom_ioctl_call[custom_param->cmd] == NULL)) {
		NPU_DRV_ERR("npu_ioctl_custom, invalid cmd %u\n", custom_param->cmd);
		return -EINVAL;
	}

	if ((custom_param->arg_size == 0) || (custom_param->arg == 0)) {
		NPU_DRV_ERR("npu_ioctl_custom, invalid args\n");
		return -EINVAL;
	}

	ret = g_npu_custom_ioctl_call[custom_param->cmd](proc_ctx, (uintptr_t)(custom_param->arg));
	if (ret != 0) {
		NPU_DRV_ERR("custom call process failed, cmd = %u\n", custom_param->cmd);
		return -EINVAL;
	}

	return ret;
}

