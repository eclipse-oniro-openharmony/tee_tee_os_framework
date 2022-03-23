#include "npu_schedule_task.h"
#include "npu_semaphore.h"
#include "npu_irq_common.h"
#include "npu_hwts_driver.h"
#include "npu_model_info_mngr.h"
#include "npu_proc_ctx.h"
#include "npu_reg.h"

#define INTR_NPU2ACPU_LITE_HWTS_NORMAL_S 601
#define INTR_NPU2ACPU_LITE_HWTS_ERROR_S 602

npu_hwts_irq_rlt_t  g_hwts_irq_rlt;

static irqreturn_t npu_ack_hwts_irq_normal(int irq, const void *data)
{
	(void)data;
	(void)irq;

	NPU_DRV_WARN("npu_ack_hwts_irq_normal irq = %d is comming", irq);
	g_hwts_irq_rlt.hwts_irq_type = NPU_HWTS_IRQ_TYPE_NORMAL;
	npu_interrupt_handle_hwts_normal();
	npu_sem_post(NPU_HWTS_SEM);
	NPU_DRV_INFO("npu_ack_hwts_irq_normal done");
	return IRQ_HANDLED;
}

static irqreturn_t npu_ack_hwts_irq_exception(int irq, const void *data)
{
	(void)data;
	(void)irq;

	NPU_DRV_WARN("npu_ack_hwts_irq_exception irq = %d is comming", irq);
	g_hwts_irq_rlt.hwts_irq_type = NPU_HWTS_IRQ_TYPE_ERROR;
	npu_interrupt_handle_hwts_error();
	npu_sem_post(NPU_HWTS_SEM);
	return IRQ_HANDLED;
}


void npu_reset_hwts_sch_result(void)
{
	g_hwts_irq_rlt.hwts_irq_type = NPU_HWTS_IRQ_TYPE_RESERVED;
	g_hwts_irq_rlt.stream_id = NPU_MAX_STREAM_ID;
	g_hwts_irq_rlt.sq_id = (DEVDRV_SEC_SQ_ID_BEGIN + DEVDRV_SEC_SQ_NUM);

	return;
}

int npu_hwts_get_sch_result(void)
{
	int ret = -1;
	if (g_hwts_irq_rlt.hwts_irq_type != NPU_HWTS_IRQ_TYPE_ERROR)
		ret = 0;

	return ret;
}

int npu_hwts_irq_init(void)
{
	int ret = 0;
	npu_reset_hwts_sch_result();
	/* register irq handler */
	ret = request_irq(INTR_NPU2ACPU_LITE_HWTS_NORMAL_S, (irq_handler_t)npu_ack_hwts_irq_normal,
		IRQF_TRIGGER_NONE, "npu_hwts_normal_handler", &g_hwts_irq_rlt);
	if (ret != 0) {
		NPU_DRV_ERR("hwts request_irq ack irq failed ret 0x%x\n", ret);
		return ret;
	}

	ret = request_irq(INTR_NPU2ACPU_LITE_HWTS_ERROR_S, (irq_handler_t)npu_ack_hwts_irq_exception,
		IRQF_TRIGGER_NONE, "npu_hwts_exception_handler", &g_hwts_irq_rlt);
	if (ret != 0) {
		NPU_DRV_ERR("hwts request_irq ack irq failed ret 0x%x\n", ret);
		goto request_failed;
	}
	return ret;

request_failed:
	free_irq(INTR_NPU2ACPU_LITE_HWTS_NORMAL_S, &g_hwts_irq_rlt);
	return ret;
}

void npu_hwts_irq_reset(void)
{
	free_irq(INTR_NPU2ACPU_LITE_HWTS_NORMAL_S, &g_hwts_irq_rlt);
	free_irq(INTR_NPU2ACPU_LITE_HWTS_ERROR_S, &g_hwts_irq_rlt);
	npu_reset_hwts_sch_result();
	return;
}


static int npu_hwts_sch_model_sq(npu_model_info_t *model_info)
{
	int ret;
	struct list_head *n = NULL;
	struct list_head *pos = NULL;
	npu_stream_info_t *stream_info = NULL;
	npu_proc_ctx_t *proc_ctx = (npu_proc_ctx_t *)model_info->proc_ctx;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;

	list_for_each_safe(pos, n, &(model_info->stream_list)) {
		stream_info = list_entry(pos, npu_stream_info_t, list_node);
		COND_RETURN_ERROR((stream_info == NULL) || (stream_info->sink_sub == NULL), -1, "invalid pointer\n");
		stream_info->sink_sub->smmu_substream_id = dev_ctx->smmu_para.ssid;
		npu_hwts_sq_t *hwts_sq = npu_alloc_hwts_sq(&(dev_ctx->sq_mngr));
		COND_RETURN_ERROR(hwts_sq == NULL, -1, "invalid hwts_sq\n");
		hwts_sq->stream_id = stream_info->stream_id;
		hwts_sq->proc_ctx = proc_ctx;
		list_add(&(hwts_sq->list_node), &(proc_ctx->sq_list));
		stream_info->sink_sub->hwts_sq_id = hwts_sq->sq_id;
		ret = npu_hwts_start_exec(stream_info, hwts_sq->sq_id);
		COND_RETURN_ERROR(ret != 0, ret, "npu_hwts_start_exec failed");
	}
	return 0;
}

int npu_task_process_model_execute(npu_model_info_mngr_t *mmgr, npu_schedule_comm_sqe_t *sch_task)
{
	int ret;
	u16 model_id = sch_task->u.model_execute_sqe.model_id;
	npu_model_info_t *model_info = npu_get_model_info(mmgr, model_id);
	COND_RETURN_ERROR(model_info == NULL, -1, "model id = %u, invalid\n", model_id);
	ret = npu_hwts_sch_model_sq(model_info);

	return ret;
}

int npu_schedule_task(npu_dev_ctx_t *dev_ctx, npu_schedule_comm_sqe_t *sch_task)
{
	int ret = 0;
	npu_model_info_mngr_t *mmgr = &(dev_ctx->model_mngr);
	uint32_t power_status;

	NPU_DRV_DEBUG("npu_schedule_task start.task type = %u\n", sch_task->type);

	if (sch_task->type == NPU_SCH_MODEL_EXECUTE) {
		power_status = npu_pm_query_power_status();
		if ((dev_ctx->power_stage != DEVDRV_PM_UP) || (power_status != DRV_NPU_POWER_ON_SEC_FLAG)) {
			NPU_DRV_ERR("wrong status: power_stage=%d, power_status=%d ! can`t send req\n", dev_ctx->power_stage, power_status);
			ret = -EFAULT;
		} else if (g_hwts_irq_rlt.hwts_irq_type == NPU_HWTS_IRQ_TYPE_ERROR) {
			NPU_DRV_ERR("wrong status: npu in exception, need resume");
			ret = -EFAULT;
		} else {
			ret = npu_task_process_model_execute(mmgr, sch_task);
			if (ret == 0) {
				return 0;
			}
		}
	}

	npu_sem_post(NPU_HWTS_SEM);
	return ret;
}

