#include "npu_hwts_sqe.h"
#include "npu_log.h"

#define DEVDRV_RT_TASK_SIZE			64
#define DEVDRV_HWTS_SQ_SLOT_SIZE	128
#define RT_TASK_ENTRY(stream_buf_addr, offset) ((stream_buf_addr) + (offset) * DEVDRV_RT_TASK_SIZE)
#define HWTS_SQE_ENTRY(hwts_sq_addr, offset) ((hwts_sq_addr) + (offset) * DEVDRV_HWTS_SQ_SLOT_SIZE)

void format_aicore_sqe(void *hwts_sqe_addr, npu_rt_hwts_task_t *hwts_task)
{
	npu_hwts_kernel_sqe_t *kernel_sqe = (npu_hwts_kernel_sqe_t *)hwts_sqe_addr;
	kernel_sqe->type = NPU_HWTS_SQE_AICORE;
	kernel_sqe->ie = 0;
	kernel_sqe->pre_p = 0;
	kernel_sqe->post_p = 0;
	kernel_sqe->wr_cqe = 0;
	kernel_sqe->rd_cond = 0;
	kernel_sqe->res0 = 0;
	kernel_sqe->l2_lock = 0;
	kernel_sqe->l2_unlock = 0;
	kernel_sqe->block_dim = hwts_task->u.kernel_task.block_dim;
	kernel_sqe->stream_id = hwts_task->stream_id;
	kernel_sqe->task_id = hwts_task->task_id;

	kernel_sqe->pc_addr_low = (u32)(hwts_task->u.kernel_task.pc_start);
	kernel_sqe->pc_addr_high = (u16)((hwts_task->u.kernel_task.pc_start) >> 32);
	kernel_sqe->kernel_credit = 2;
	kernel_sqe->res2 = 0;
	kernel_sqe->icache_prefetch_cnt = 1;

	kernel_sqe->param_addr_low = (u32)(hwts_task->u.kernel_task.param_base);
	kernel_sqe->param_addr_high = (u16)((hwts_task->u.kernel_task.param_base) >> 32);
	kernel_sqe->l2_in_main = 0xFF; // dirty_code
	kernel_sqe->res3 = 0;

	kernel_sqe->literal_addr_low = (u32)(hwts_task->u.kernel_task.literal_src_addr);
	kernel_sqe->literal_addr_high = (u16)(hwts_task->u.kernel_task.literal_src_addr >> 32);
	kernel_sqe->res4 = 0;

	kernel_sqe->literal_base_ub = hwts_task->u.kernel_task.literal_dst_base;
	kernel_sqe->res5 = 0;

	kernel_sqe->literal_buff_len = hwts_task->u.kernel_task.literal_size;
	kernel_sqe->res6 = 0;

	NPU_DRV_DEBUG("kernel_sqe= %pK, struct size= %d, stream_id= %u, task_id= %u, pc_start= 0x%llx, param_base= 0x%llx\n",
		kernel_sqe,
		sizeof(npu_hwts_kernel_sqe_t),
		hwts_task->stream_id,
		hwts_task->task_id,
		hwts_task->u.kernel_task.pc_start,
		hwts_task->u.kernel_task.param_base);
	return;
}

int npu_format_hwts_sqe(void *sq_addr, void *task_addr, u16 count)
{
	u8 *hwts_sq_base = sq_addr;
	u8 *stream_buf_addr_base = task_addr;
	u8 *hwts_sqe = NULL;
	npu_rt_hwts_task_t *hwts_task = NULL;
	u32 i;

	if (sq_addr == NULL) {
		NPU_DRV_ERR("sq_addr is null\n");
		return -1;
	}
	if (task_addr == NULL) {
		NPU_DRV_ERR("task_addr is null\n");
		return -1;
	}

	NPU_DRV_DEBUG("sq_addr:0x%llx, task_addr:0x%llx, count:%u",
		sq_addr, task_addr, count);
	for (i = 0; i < count; i++) {
		hwts_task = (npu_rt_hwts_task_t *)RT_TASK_ENTRY(stream_buf_addr_base, i);
		hwts_sqe = HWTS_SQE_ENTRY(hwts_sq_base, i);

		if (hwts_task->type != NPU_HWTS_SQE_AICORE) {
			NPU_DRV_ERR("invalid task_id:%u, type:%u\n", hwts_task->task_id, hwts_task->type);
			break;
		}
		format_aicore_sqe((void *)hwts_sqe, hwts_task);
	}

	NPU_DRV_DEBUG("npu_format_hwts_sqe end\n");

	return 0;
}

