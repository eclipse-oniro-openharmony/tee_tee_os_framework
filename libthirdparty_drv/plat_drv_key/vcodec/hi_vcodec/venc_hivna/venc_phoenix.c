/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: vcodec secure os part
 * Author:
 * Create: 2019-12-1
 */

#include "venc_tee.h"

#define SMRX_ID_SIZE 37
#define HIVENC0_REG_BASE 0xe9280000
#define HIVENC1_REG_BASE 0xe92c0000
#define HIVENC_SMMU_COMMON_OFFSET 0x20000

#define HIVENC0_SMMU_COMMON_BASE (HIVENC0_REG_BASE + HIVENC_SMMU_COMMON_OFFSET)
#define HIVENC1_SMMU_COMMON_BASE (HIVENC1_REG_BASE + HIVENC_SMMU_COMMON_OFFSET)

#define SMMU_SCR   0x0000
#define SMMU_SCR_P 0x10210
#define SMMU_SMRX_P 0x10000
#define SMMU_ERR_ADDR_MSB  0x0300
#define SMMU_ERR_RDADDR    0x0304
#define SMMU_ERR_WRADDR    0x0308

#define SMMU_PCB_TTBR      0x10218
#define SMMU_PCB_TTBCR     0X1021C
#define SMMU_PCB_TTBR_MSB  0x10228
#define SMMU_CB_TTBR0      0x0204
#define SMMU_CB_TTBR_MSB   0x0224

#define SMMU_ERR_ADD_MSB_P 0x10230
#define SMMU_ERR_RDADDR_P  0x10234
#define SMMU_ERR_WRADDR_P  0x10238

HI_U32 *g_smmuCommonBase;
static const HI_U32 g_vencSmmuCommonBase[] = { HIVENC0_SMMU_COMMON_BASE, HIVENC1_SMMU_COMMON_BASE };

#define RD_SMMU_COMMON_VREG(reg, dat) \
do { \
    (dat) = *((volatile HI_U32 *)((HI_U8 *)g_smmuCommonBase + (reg))); \
} while (0)

#define WR_SMMU_COMMON_VREG(reg, dat) \
do { \
    *((volatile HI_U32 *)((HI_U8 *)g_smmuCommonBase + (reg))) = (dat); \
} while (0)

static HI_VOID SetCommonReg(HI_U32 addr, HI_U32 val, HI_U32 bw, HI_U32 bs)
{
    HI_U32 mask = (1UL << bw) - 1UL;
    HI_U32 tmp = 0;

    RD_SMMU_COMMON_VREG(addr, tmp);
    tmp &= ~(mask << bs); /* lint !e502 */
    WR_SMMU_COMMON_VREG(addr, tmp | ((val & mask) << bs)); /* lint !e665 */
}

void ConfigSecurityMaster(HI_U32 coreId)
{
    HI_U32 datal = 0;
    HI_U32 datah = 0;

    g_smmuCommonBase = (HI_U32 *)(uintptr_t)g_vencSmmuCommonBase[coreId];

    RD_SMMU_COMMON_VREG(SMMU_CB_TTBR0, datal);
    RD_SMMU_COMMON_VREG(SMMU_CB_TTBR_MSB, datah);

    SetCommonReg(SMMU_SCR, 0x60, 6, 20);  // offset: 20, length: 6, value: 0x60
    SetCommonReg(SMMU_PCB_TTBR, datal, 32, 0); // offset: 0, length: 32
    SetCommonReg(SMMU_PCB_TTBR_MSB, datah, 7, 0); // offset: 0, length: 7
    SetCommonReg(SMMU_PCB_TTBCR, 1, 1, 0); // offset: 0, length: 1, value: 1
    SetCommonReg(SMMU_SCR_P, 0, 1, 8); // offset: 8, length: 1, value: 0
    SetCommonReg(SMMU_SCR_P, 1, 1, 0); // offset: 0, length: 1, value: 1
    HI_U32 i;
    for (i = 0; i < SMRX_ID_SIZE; i++) {
        SetCommonReg(SMMU_SMRX_P + i * 0x4, 1, 1, 0); // offset: 0, length: 1, value: 1
    }
}

void ResetSecurityMaster(HI_U32 coreId)
{
    g_smmuCommonBase = (HI_U32 *)(uintptr_t)g_vencSmmuCommonBase[coreId];
    SetCommonReg(SMMU_PCB_TTBR, 0x00000000, 32, 0); // offset: 0, length: 32, value: 0x00000000
    SetCommonReg(SMMU_PCB_TTBR_MSB, 0x00, 7, 0); // offset: 0, length: 7 value: 0x00
    SetCommonReg(SMMU_PCB_TTBCR, 0, 1, 0); // offset: 0, length: 1 value: 0
    SetCommonReg(SMMU_SCR_P, 1, 1, 8); // offset: 8, length: 1 value: 1
    SetCommonReg(SMMU_SCR_P, 0, 1, 0); // offset: 0, length: 1 value: 0
    HI_U32 i;
    for (i = 0; i < SMRX_ID_SIZE; i++) {
        SetCommonReg(SMMU_SMRX_P + i * 0x4, 0, 1, 0); // offset: 0, length: 1 value: 0
    }
}
