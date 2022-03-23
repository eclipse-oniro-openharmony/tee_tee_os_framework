/*
 * npu_reg.h
 *
 * about npu reg
 *
 * Copyright (c) 2012-2019 Huawei Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */
#ifndef __NPU_REG_H
#define __NPU_REG_H

#include "npu_platform_register.h"

#define DRV_NPU_POWER_STATUS_REG SOC_SCTRL_SCBAKDATA28_ADDR(SOC_ACPU_SCTRL_BASE_ADDR)
#define DRV_NPU_POWER_OFF_FLAG   0x1A1A
#define DRV_NPU_POWER_ON_FLAG    0x2B2B
#define DRV_NPU_POWER_ON_SEC_FLAG 0xC4C4

typedef enum {
	DEVDRV_REG_POWER_STATUS,
	DEVDRV_REG_MAX_REG,
} npu_reg_type;

uint32_t npu_pm_query_power_status(void);

#endif
