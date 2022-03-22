/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: imp mspe smmu v2.
 * Author: Security Engine
 * Create: 2020/07/16
 */
#ifndef __MSPE_SMMU_V2_H__
#define __MSPE_SMMU_V2_H__

#include <pal_types.h>

/* master id, hardware define */
enum mspe_mid {
	MSPE_MID_SCE1 = 125,
	MSPE_MID_SCE2 = 126,
};

/* rd/wr config, secure/non-secure/protect */
enum mspe_smmu_rd_wr_cfg {
	MSPE_SMMU_SECURE = 0,
	MSPE_SMMU_PROTECT,
	MSPE_SMMU_NON_SECURE,
	MSPE_SMMU_BYPASS_SECURE,
	MSPE_SMMU_BYPASS_PROTECT,
	MSPE_SMMU_BYPASS_NON_SECURE,
};

void mspe_smmu_set_pgt_addr(u64 pgt_pa, u32 is_sec);
void mspe_smmu_enable(u32 mid, u32 rd_cfg, u32 wr_cfg);
void mspe_smmu_disable(u32 mid);
void mspe_smmu_bypass(void);

#endif
