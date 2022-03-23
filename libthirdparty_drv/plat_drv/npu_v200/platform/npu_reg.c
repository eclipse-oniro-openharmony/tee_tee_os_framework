#include "npu_base_define.h"
#include "svm.h"
#include "npu_reg.h"
#include "npu_log.h"

#define DRV_NPU_POWER_STATUS_REG SOC_SCTRL_SCBAKDATA28_ADDR(SOC_ACPU_SCTRL_BASE_ADDR)

static uint32_t npu_plat_regs[DEVDRV_REG_MAX_REG] = {
	[DEVDRV_REG_POWER_STATUS] = DRV_NPU_POWER_STATUS_REG,
};

/* return:  0--error */
static uint32_t npu_plat_get_vaddr(npu_reg_type reg_type)
{
	if (reg_type >= DEVDRV_REG_MAX_REG) {
		NPU_DRV_ERR("invalid reg_type %d\n", reg_type);
		return 0;
	}

	return npu_plat_regs[reg_type];
}

uint32_t npu_pm_query_power_status(void)
{
	uint32_t  readval, addr;
	addr = npu_plat_get_vaddr(DEVDRV_REG_POWER_STATUS);
	if (addr == 0) {
		return DRV_NPU_POWER_ON_SEC_FLAG;
	}

	readval = hisi_readl(addr);
	NPU_DRV_DEBUG("readval = 0x%x, addr = 0x%x\n", readval, addr);
	return readval;
}

