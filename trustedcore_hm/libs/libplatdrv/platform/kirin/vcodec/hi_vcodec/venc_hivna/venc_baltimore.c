/*
* Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
* Description: vcodec drm for baltimore
* Author:MediaOS
* Create: 2020-4-14
*/

#include "venc_tee.h"

/* baltimore venc base address */
#define HIVENC_BASE_ADDR 0xE9280000
/* baltimore venc area size */
#define SMRX_ID_SIZE 64
#define HIVENC_SMMU_TBU_OFFSET 0x20000
#define HIVENC_SMMU_TBU_PROT_EN 0x1100
#define HIVENC_SMMU_TBU_ADDR (HIVENC_BASE_ADDR + HIVENC_SMMU_TBU_OFFSET)

HI_U32 *g_smmuTBUBase = (HI_U32 *)(intptr_t)HIVENC_SMMU_TBU_ADDR;

#define RD_SMMU_COMMON_VREG(reg, dat) \
do { \
    (dat) = *((volatile HI_U32 *)((HI_U8 *)g_smmuTBUBase + (reg))); \
} while (0)

#define WR_SMMU_COMMON_VREG(reg, dat) \
do { \
    *((volatile HI_U32 *)((HI_U8 *)g_smmuTBUBase + (reg))) = (dat); \
} while (0)

static void SetCommonReg(HI_U32 addr, HI_U32 val, HI_U32 bw, HI_U32 bs)
{
    HI_U32 mask = (1UL << bw) - 1UL;
    HI_U32 tmp = 0;

    RD_SMMU_COMMON_VREG(addr, tmp);
    tmp &= ~(mask << bs);
    WR_SMMU_COMMON_VREG(addr, tmp | ((val & mask) << bs));
}

static void SetSmmuTbuProtected(bool smmuSecEnable)
{
    for (int i = 0; i < SMRX_ID_SIZE; i++) {
        if (i == 16 || i == 26) { // 16, 26: unprotected addr of cmd mode
            continue;
        }
        SetCommonReg(HIVENC_SMMU_TBU_PROT_EN + i * 0x4, smmuSecEnable ? 1 : 0, 1, 0);
    }
}

void ConfigSecurityMaster(HI_U32 coreID __unused)
{
    SetSmmuTbuProtected(true);
}

void ResetSecurityMaster(HI_U32 coreID __unused)
{
    SetSmmuTbuProtected(false);
}
