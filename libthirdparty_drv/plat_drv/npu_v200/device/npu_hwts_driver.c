#include "npu_hwts_driver.h"
#include "npu_log.h"
#include "soc_acpu_baseaddr_interface.h"
#include "soc_npu_hwts_interface.h"
#include "npu_shm_info.h"
#include "npu_proc_ctx.h"
#include "npu_reg.h"
#include "npu_dev_ctx_mngr.h"

#define REG_DEF_HWTS_BASE_ADDR					  (SOC_ACPU_hwts_BASE_ADDR)

void npu_clear_hwts_normal_interrupt(u32 type, u64 *value)
{
	u64 addr = 0;
	switch (type) {
	case HWTS_SQ_DONE_S:
		addr = SOC_NPU_HWTS_HWTS_L2_NORMAL_SQ_DONE_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	case HWTS_CQE_WRITTEN_S:
		addr = SOC_NPU_HWTS_HWTS_L2_NORMAL_CQE_WRITTEN_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	case HWTS_L2_BUF_SWAP_OUT_S:
		addr = SOC_NPU_HWTS_HWTS_L2_NORMAL_L2BUF_SWAPOUT_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	case HWTS_L2_BUF_SWAP_IN_S:
		addr = SOC_NPU_HWTS_HWTS_L2_NORMAL_L2BUF_SWAPIN_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	case HWTS_TASK_PAUSED_S:
		addr = SOC_NPU_HWTS_HWTS_L2_NORMAL_TASK_PAUSED_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	case HWTS_CQ_FULL_S:
		addr = SOC_NPU_HWTS_HWTS_L2_NORMAL_CQ_FULL_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	case HWTS_POST_PAUSED_S:
		addr = SOC_NPU_HWTS_HWTS_L2_NORMAL_POST_PAUSED_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	case HWTS_PRE_PAUSED_S:
		addr = SOC_NPU_HWTS_HWTS_L2_NORMAL_PRE_PAUSED_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	case HWTS_SQE_DONE_S:
		addr = SOC_NPU_HWTS_HWTS_L2_NORMAL_SQE_DONE_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	default:
		NPU_DRV_ERR("hwts unsupport interrupt type=0x%x",type);
		break;
	}

	if (addr != 0) {
		*value = npu_read64(addr);
		npu_write64(*value,addr);
	}
	return;
}

void npu_clear_hwts_exception_interrupt(u32 type, u64 *value)
{
	u64 addr = 0;
	switch (type) {
	case HWTS_TASK_ERROR_S:
		addr = SOC_NPU_HWTS_HWTS_L2_TASK_ERROR_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	case HWTS_TASK_TIMEOUT_S:
		addr = SOC_NPU_HWTS_HWTS_L2_TASK_TIMEOUT_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	case HWTS_TASK_TRAP_S:
		addr = SOC_NPU_HWTS_HWTS_L2_TASK_TRAP_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	case HWTS_SQE_ERROR_S:
		addr = SOC_NPU_HWTS_HWTS_L2_SQE_ERROR_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	case HWTS_SW_STATUS_ERROR_S:
		addr = SOC_NPU_HWTS_HWTS_L2_SW_STATUS_ERROR_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
		break;

	case HWTS_BUS_ERROR_S:
		NPU_DRV_INFO( "bus error, need to reboot");
		break;

	case HWTS_POOL_CONFLICT_ERROR_S:
		NPU_DRV_INFO( "POOL CONFLICT ERROR");
		break;

	default:
		NPU_DRV_ERR("hwts unsupport interrupt type=0x%x",type);
		break;
	}

	if (addr != 0) {
		*value = npu_read64(addr);
		npu_write64(*value,addr);
	}
	return;
}

void npu_clear_hwts_channel_sq_en(u16 sq_id)
{
	u64 hwts_reg_addr;
	u64 reg_val;

	hwts_reg_addr = SOC_NPU_HWTS_HWTS_SQ_CFG0_ADDR(REG_DEF_HWTS_BASE_ADDR, sq_id);
	reg_val = npu_read64(hwts_reg_addr);
	TS_BITMAP_CLR(reg_val, SOC_NPU_HWTS_HWTS_SQ_CFG0_sq_en_START);

	npu_write64(reg_val, hwts_reg_addr);
}

int npu_hwts_start_exec(npu_stream_info_t *stream_info, u16 sq_id)
{
	u64 reg_val;
	u64 hwts_reg_addr;

	npu_proc_ctx_t *proc_ctx = (npu_proc_ctx_t *)stream_info->proc_ctx;
	NPU_DRV_INFO( "hwts_sq_id=%u, priority=%d", sq_id, (u16)stream_info->priority);
	COND_RETURN_ERROR((sq_id < DEVDRV_SEC_SQ_ID_BEGIN) || (sq_id >= (DEVDRV_SEC_SQ_ID_BEGIN + DEVDRV_SEC_SQ_NUM)),
		-1, "invalid sq_id=%u \n", sq_id);

	NPU_DRV_INFO( "step 1. write hwts sq");

	// step 1. write hwts sq
	// write sq base addr, using physical address
	hwts_reg_addr = SOC_NPU_HWTS_HWTS_SQ_BASE_ADDR_ADDR(REG_DEF_HWTS_BASE_ADDR, sq_id);
	reg_val = (stream_info->sink_sub->phy_addr << SOC_NPU_HWTS_HWTS_SQ_BASE_ADDR_sq_base_addr_START) |
		(0ULL << SOC_NPU_HWTS_HWTS_SQ_BASE_ADDR_sq_base_addr_is_virtual_START);

	npu_write64(reg_val, hwts_reg_addr);

	reg_val = npu_read64(hwts_reg_addr);
	NPU_DRV_DEBUG( "HWTS_SQ_BASE after read  val = %llx. addr = %llx", reg_val, hwts_reg_addr);

	// step 2. Set the info of corresponding cq
	// associate cq buffer with sq
	u16 ssid = proc_ctx->dev_ctx->smmu_para.ssid;
	hwts_reg_addr = SOC_NPU_HWTS_HWTS_SQ_CFG1_ADDR(REG_DEF_HWTS_BASE_ADDR, sq_id);

	reg_val = npu_read64(hwts_reg_addr);
	REG_FIELD_INSERT(reg_val,
		SOC_NPU_HWTS_HWTS_SQ_CFG1_sq_cqid_END - SOC_NPU_HWTS_HWTS_SQ_CFG1_sq_cqid_START + 1,
		SOC_NPU_HWTS_HWTS_SQ_CFG1_sq_cqid_START,
		sq_id);
	REG_FIELD_INSERT(reg_val,
		SOC_NPU_HWTS_HWTS_SQ_CFG1_sq_aic_poolid_END - SOC_NPU_HWTS_HWTS_SQ_CFG1_sq_aic_poolid_START + 1,
		SOC_NPU_HWTS_HWTS_SQ_CFG1_sq_aic_poolid_START,
		0); // default aicore pool 0
	REG_FIELD_INSERT(reg_val,
		SOC_NPU_HWTS_HWTS_SQ_CFG1_sq_smmu_substream_id_END - SOC_NPU_HWTS_HWTS_SQ_CFG1_sq_smmu_substream_id_START + 1,
		SOC_NPU_HWTS_HWTS_SQ_CFG1_sq_smmu_substream_id_START,
		ssid); // smmu substream id

	npu_write64(reg_val, hwts_reg_addr);

	// write cq base addr
	hwts_reg_addr = SOC_NPU_HWTS_HWTS_CQ_BASE_ADDR_ADDR(REG_DEF_HWTS_BASE_ADDR, sq_id);//channel_id or cq_id?
	u64 cq_base_addr = proc_ctx->dev_ctx->shm_mem[NPU_SHM_CQ].phy_base;
	reg_val = (cq_base_addr << SOC_NPU_HWTS_HWTS_CQ_BASE_ADDR_cq_base_addr_START) |
		(0ULL << SOC_NPU_HWTS_HWTS_CQ_BASE_ADDR_cq_base_addr_is_virtual_START);
	npu_write64(reg_val, hwts_reg_addr);

	// set cq tail / cq length
	hwts_reg_addr = SOC_NPU_HWTS_HWTS_CQ_CFG_ADDR(REG_DEF_HWTS_BASE_ADDR, sq_id);//channel_id or cq_id?
	reg_val = (0 << SOC_NPU_HWTS_HWTS_CQ_CFG_cq_tail_START) |
		(HWTS_CQ_LENGTH << SOC_NPU_HWTS_HWTS_CQ_CFG_cq_length_START);
	npu_write64(reg_val, hwts_reg_addr);

	// set cq head
	hwts_reg_addr = SOC_NPU_HWTS_HWTS_CQ_DB_ADDR(REG_DEF_HWTS_BASE_ADDR, sq_id);//channel_id or cq_id?
	reg_val = (0 << SOC_NPU_HWTS_HWTS_CQ_DB_cq_head_START);
	npu_write64(reg_val, hwts_reg_addr);

	// set sq tail
	hwts_reg_addr = SOC_NPU_HWTS_HWTS_SQ_DB_ADDR(REG_DEF_HWTS_BASE_ADDR, sq_id);
	u32 sqe_count = stream_info->sink_sub->sqe_count;
	reg_val = (sqe_count << SOC_NPU_HWTS_HWTS_SQ_DB_sq_tail_START);
	npu_write64(reg_val, hwts_reg_addr);

	// sq head length info and sq en
	hwts_reg_addr = SOC_NPU_HWTS_HWTS_SQ_CFG0_ADDR(REG_DEF_HWTS_BASE_ADDR, sq_id);
	reg_val = (0 << SOC_NPU_HWTS_HWTS_SQ_CFG0_sq_head_START) |
		((HWTS_SQ_LENGTH - 1) << SOC_NPU_HWTS_HWTS_SQ_CFG0_sq_length_START) |
		(1ULL << SOC_NPU_HWTS_HWTS_SQ_CFG0_sq_en_START);
	npu_write64(reg_val, hwts_reg_addr);

	NPU_DRV_INFO( "ready to dsb");

	hwts_reg_addr = SOC_NPU_HWTS_HWTS_SQ_SEC_EN_ADDR(REG_DEF_HWTS_BASE_ADDR, 0);
	reg_val = npu_read64(hwts_reg_addr);
	NPU_DRV_DEBUG( "testtest SDMA_NS_SQ after read  val = %llx. addr = %llx", reg_val, hwts_reg_addr);

	// dsb
	dsb();

	NPU_DRV_INFO( "npu_hwts_start_exec end.");
	return 0;
}

void npu_interrupt_handle_hwts_normal()
{
	u64 L1_reg_val = 0;
	u64 hwts_l1_int_addr;
	u32 type = 0;
	u64 normal_status = 0;
	u32 sq_id = 0;
	npu_dev_ctx_t *dev_ctx = npu_get_dev_ctx(0);
	uint32_t power_status = npu_pm_query_power_status();

	if (power_status != DRV_NPU_POWER_ON_SEC_FLAG) {
		NPU_DRV_INFO("npu is power down");
		return;
	}

	hwts_l1_int_addr = SOC_NPU_HWTS_HWTS_L1_NORMAL_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR);
	L1_reg_val = npu_read64(hwts_l1_int_addr);
	NPU_DRV_INFO("hwts_normal L1_reg_val = 0x%llx", L1_reg_val);

	for (; type = (__builtin_ffsll(L1_reg_val) - 1), type < HWTS_NORMAL_IRQ_MAX;
		TS_BITMAP_CLR(L1_reg_val, type)) {
		npu_clear_hwts_normal_interrupt(type, &normal_status);
	}

	for (; sq_id = (__builtin_ffsll(normal_status) - 1), sq_id < HWTS_SQ_NUM_MAX;
		TS_BITMAP_CLR(normal_status, sq_id)) {
		npu_clear_hwts_channel_sq_en(sq_id);
		npu_hwts_sq_t *hwts_sq = npu_get_hwts_sq(&(dev_ctx->sq_mngr), sq_id);
		COND_RETURN_VOID(hwts_sq == NULL, "invalid pointer\n");
		hwts_sq->proc_ctx = NULL;
		list_del(&(hwts_sq->list_node));
		npu_free_hwts_sq(&(dev_ctx->sq_mngr), sq_id);
	}
}

void npu_interrupt_handle_hwts_error()
{
	uint64_t L1_reg_val = 0;
	uint64_t hwts_l1_int_addr;
	uint32_t type = 0;
	u64 err_status = 0;
	u32 sq_id = 0;
	npu_dev_ctx_t *dev_ctx = npu_get_dev_ctx(0);
	uint32_t power_status = npu_pm_query_power_status();

	if (power_status != DRV_NPU_POWER_ON_SEC_FLAG) {
		NPU_DRV_INFO("npu is power down");
		return;
	}

	hwts_l1_int_addr = SOC_NPU_HWTS_HWTS_L1_ERROR_S_INTERRUPT_ADDR(REG_DEF_HWTS_BASE_ADDR);
	L1_reg_val = npu_read64(hwts_l1_int_addr);
	NPU_DRV_WARN("hwts_err L1_reg_val = 0x%llx", L1_reg_val);
	for (; type = (__builtin_ffsll(L1_reg_val) - 1), type < HWTS_NORMAL_IRQ_MAX;
		 TS_BITMAP_CLR(L1_reg_val, type)) {
		npu_clear_hwts_exception_interrupt(type, &err_status);
	}

	for (; sq_id = (__builtin_ffsll(err_status) - 1), sq_id < HWTS_SQ_NUM_MAX;
		TS_BITMAP_CLR(err_status, sq_id)) {
		npu_clear_hwts_channel_sq_en(sq_id);
		npu_hwts_sq_t *hwts_sq = npu_get_hwts_sq(&(dev_ctx->sq_mngr), sq_id);
		COND_RETURN_VOID(hwts_sq == NULL, "invalid pointer\n");
		hwts_sq->proc_ctx = NULL;
		list_del(&(hwts_sq->list_node));
		npu_free_hwts_sq(&(dev_ctx->sq_mngr), sq_id);
	}
}

