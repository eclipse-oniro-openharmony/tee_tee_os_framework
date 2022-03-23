/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu reg
 */
#ifndef __NPU_REG_H
#define __NPU_REG_H

#include "npu_platform.h"

#define DRV_NPU_POWER_OFF_FLAG   0x1A1A
#define DRV_NPU_POWER_ON_FLAG    0x2B2B
#define NPU_POWER_ON             0x1
#define NPU_POWER_OFF            0x0

typedef enum {
	DEVDRV_REG_POWER_STATUS,
	DEVDRV_REG_MAX_REG,
}npu_reg_type;

int npu_plat_unmap_reg(struct npu_platform_info *plat_info);
int npu_plat_parse_reg_desc(struct npu_platform_info *plat_info);
unsigned npu_plat_get_vaddr(npu_reg_type reg_type);
int npu_pm_query_ree_status(void);

void npu_reg_update(uint64_t addr, uint32_t mask, uint32_t value);
int npu_read_wait(uint64_t addr, uint32_t expect_val, uint32_t mask, uint32_t wait_time);

#endif
