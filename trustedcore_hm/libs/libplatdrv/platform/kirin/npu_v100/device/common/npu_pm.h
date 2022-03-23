/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu power
 */
#ifndef __NPU_PM_H
#define __NPU_PM_H
#include <sre_typedef.h>
#include "npu_common.h"

enum npu_power_mode {
	DEVDRV_LOW_POWER = 0x0,
	DEVDRV_NORMAL_POWER,
	DEVDRV_MAX_MODE,
};

enum npu_power_stage {
	DEVDRV_PM_DOWN,
	DEVDRV_PM_NPUCPU,
	DEVDRV_PM_TS,
	DEVDRV_PM_UP,
};

int npu_powerup(struct npu_dev_ctx *dev_ctx);

int npu_powerdown(struct npu_dev_ctx *dev_ctx);

#endif
