/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu power
 */

#include "npu_pm.h"

#include <errno.h>
#include "drv_log.h"
#include "npu_platform.h"
#include "npu_shm.h"
#include "npu_adapter.h"

int npu_powerup(struct npu_dev_ctx *dev_ctx)
{
	u32 *ts_status = NULL;
	int ret;
	if (atomic_read(&dev_ctx->poweron_access) == 0) {
		NPU_WARN("maybe npu dev %d has power on!\n", dev_ctx->devid);
		return 0;
	}

	atomic_dec(&dev_ctx->poweron_access);
	ret = npu_plat_power_up(dev_ctx->hisi_svm);
	if (ret != 0) {
		atomic_inc(&dev_ctx->poweron_access);
		NPU_ERR("npu dev %d has power on failed!\n", dev_ctx->devid);
		return ret;
	}

	dev_ctx->power_stage = DEVDRV_PM_UP;
	dev_ctx->ts_work_status = 1;
	ts_status = npu_get_ts_work_status(dev_ctx->devid, 0);
	if (ts_status != NULL) {
		*ts_status = DEVDRV_TS_WORK;
	}
	NPU_WARN("npu dev %d has power on success!\n", dev_ctx->devid);
	atomic_dec(&dev_ctx->poweron_success);

	ret = npu_map_internal_reg(dev_ctx);
	if (ret) {
		NPU_ERR("npu_map_internal_reg failed\n");
	}

	return 0;
}

int npu_powerdown(struct npu_dev_ctx *dev_ctx)
{
	u32 *ts_status = NULL;
	int ret;

	if (atomic_read(&dev_ctx->poweron_success) != 0) {
		NPU_WARN("npu dev %d not poweron success or been powered down before,"
			"no need power off again!\n", dev_ctx->devid);
		return 0;
	}

	npu_unmap_internal_reg(dev_ctx);
	// 1 if no power down action
	// 2 power down failed
	// 3 should confirm chip colleage
	atomic_inc(&dev_ctx->poweron_access);
	atomic_inc(&dev_ctx->poweron_success);
	ret = npu_plat_power_down(dev_ctx->hisi_svm);
	if (ret != 0) {
		NPU_ERR("npu dev %d power down failed!\n", dev_ctx->devid);
		return ret;
	}

	dev_ctx->power_stage = DEVDRV_PM_DOWN;
	dev_ctx->ts_work_status = 0;
	ts_status = npu_get_ts_work_status(dev_ctx->devid, 0);
	if (ts_status != NULL) {
		*ts_status = DEVDRV_TS_DOWN;
	}

	NPU_WARN("npu dev %d has power down success!\n", dev_ctx->devid);
	return ret;
}
