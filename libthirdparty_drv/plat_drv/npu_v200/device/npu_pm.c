#include "npu_pm.h"
#include "npu_log.h"
#include "npu_adapter.h"

int npu_powerup(npu_dev_ctx_t *dev_ctx)
{
	int ret;
	void *smmu_para = NULL;

	if (dev_ctx->power_stage == DEVDRV_PM_UP) {
		NPU_DRV_ERR("maybe npu dev %d has power on!\n", dev_ctx->dev_id);
		return 0;
	}

	smmu_para = (void *)&(dev_ctx->smmu_para);
	ret = npu_plat_power_up(smmu_para);
	if (ret != 0) {
		NPU_DRV_ERR("npu dev %d has power on failed!\n", dev_ctx->dev_id);
		return ret;
	}

	dev_ctx->power_stage = DEVDRV_PM_UP;
	NPU_DRV_INFO("npu dev %d has power on success!\n", dev_ctx->dev_id);

	return 0;
}

int npu_powerdown(npu_dev_ctx_t *dev_ctx)
{
	int ret;
	void *smmu_para = NULL;

	if (dev_ctx->power_stage == DEVDRV_PM_DOWN) {
		NPU_DRV_WARN("npu dev %d not poweron success or been powered down before,"
			"no need power off again!\n", dev_ctx->dev_id);
		return 0;
	}

	smmu_para = (void *)&(dev_ctx->smmu_para);
	ret = npu_plat_power_down(smmu_para);
	if (ret != 0) {
		NPU_DRV_ERR("npu dev %d power down failed!\n", dev_ctx->dev_id);
		return ret;
	}

	dev_ctx->power_stage = DEVDRV_PM_DOWN;
	NPU_DRV_INFO("npu dev %d has power down success!\n", dev_ctx->dev_id);

	return ret;
}

