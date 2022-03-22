/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.
 * Description: init function file for Hisilicon SSM
 * Author: ssm group
 * Create: 2019/12/11
 * Notes:
 */

#include "iommu_tag_init.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_ssm.h"
#include "hi_tee_drv_mem.h"

#define CLEAR_DATA              0
#define SHIFT_FOR_HIGH_32       32
#define SHIFT_FOR_HIGH_16       16

static hi_u64 g_read_err_addr = 0;
static hi_u64 g_write_err_addr = 0;
static hi_u64 g_sec_pgtbl_addr = 0;

static inline hi_u32 readl(hi_u32 addr)
{
    unsigned int __v = *(volatile unsigned int *)(hi_tee_drv_hal_phys_to_virt(addr));
    asm volatile("dsb");
    return __v;
}

static inline hi_void writel(hi_u32 val, hi_u32 addr)
{
    asm volatile("dsb");
    *(volatile unsigned int *)(hi_tee_drv_hal_phys_to_virt(addr)) = (val);
    asm volatile("dsb");
}

hi_s32 ssm_set_reg(hi_u32 addr, hi_u32 val)
{
    writel(val, addr);
    if (readl(addr) != val) {
        hi_tee_drv_hal_printf("reg write fail, need:%x,cur:%x\n", val, readl(addr));
        return HI_FAILURE;
    } else {
        return HI_SUCCESS;
    }
}

static hi_void iommu_tag_set(const hi_u32 base_addr, const hi_u32 tag_offset_l, const hi_u32 tag_offset_h,
    const hi_u32 tag_low_value, const hi_u32 tag_high_value)
{
    if (tag_offset_l != HI_NULL) {
        writel(CLEAR_DATA, base_addr + tag_offset_l);
        writel(tag_low_value, base_addr + tag_offset_l);
        if (readl(base_addr + tag_offset_l) != tag_low_value) {
            hi_tee_drv_hal_printf("reg write fail,need:%x,cur:%x\n", tag_low_value, readl(base_addr + tag_offset_l));
        }
    }

    if (tag_offset_h != HI_NULL) {
        writel(CLEAR_DATA, base_addr + tag_offset_h);
        writel(tag_high_value, base_addr + tag_offset_h);
        if (readl(base_addr + tag_offset_h) != tag_high_value) {
            hi_tee_drv_hal_printf("reg write fail,need:%x,cur:%x\n", tag_high_value, readl(base_addr + tag_offset_h));
        }
    }
    return;
}

static hi_void iommu_tag_set_onereg(const hi_u32 base_addr, const hi_u32 reg_offset, const hi_u32 value)
{
    writel(CLEAR_DATA, base_addr + reg_offset);
    writel(value, base_addr + reg_offset);
    if (readl(base_addr + reg_offset) != value) {
        hi_tee_drv_hal_printf("reg write fail,need:%x,cur:%x\n", value, readl(base_addr + reg_offset));
    }

    return;
}

/* demux */
hi_void iommu_config_demux(void)
{
    iommu_tag_set(REG_DMX_BASE, REG_DMX_OFFSET_WTAG_L, REG_DMX_OFFSET_WTAG_H, DMX_WTAG_VAL_L32, DMX_WTAG_VAL_H32);
    iommu_tag_set(REG_DMX_BASE, REG_DMX_OFFSET_RTAG_L, REG_DMX_OFFSET_RTAG_H, DMX_RTAG_VAL_L32, DMX_RTAG_VAL_H32);
    return;
}

/* tscipher */
hi_void iommu_config_tscipher(void)
{
    iommu_tag_set(REG_TSCIPHER_BASE, REG_TSCIPHER_OFFSET_WTAG_L, REG_TSCIPHER_OFFSET_WTAG_H,
        TSCIPHER_WTAG_VAL_L32, TSCIPHER_WTAG_VAL_H32);
    iommu_tag_set(REG_TSCIPHER_BASE, REG_TSCIPHER_OFFSET_RTAG_L, REG_TSCIPHER_OFFSET_RTAG_H,
        TSCIPHER_RTAG_VAL_L32, TSCIPHER_RTAG_VAL_H32);
    iommu_tag_set(REG_TSCIPHER_BASE, REG_TSCIPHER_OFFSET_R_ERR_L, REG_TSCIPHER_OFFSET_R_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_TSCIPHER_BASE, REG_TSCIPHER_OFFSET_W_ERR_L, REG_TSCIPHER_OFFSET_W_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));
    return;
}

/* mcipher */
hi_void iommu_config_mcipher(void)
{
    iommu_tag_set(REG_MCIPHER_BASE, REG_MCIPHER_OFFSET_WTAG_L, REG_MCIPHER_OFFSET_WTAG_H,
        MCIPHER_WTAG_VAL_L32, MCIPHER_WTAG_VAL_H32);
    iommu_tag_set(REG_MCIPHER_BASE, REG_MCIPHER_OFFSET_RTAG_L, REG_MCIPHER_OFFSET_RTAG_H,
        MCIPHER_RTAG_VAL_L32, MCIPHER_RTAG_VAL_H32);
    iommu_tag_set(REG_MCIPHER_BASE, REG_MCIPHER_HASH_OFFSET_R_TAG_L, REG_MCIPHER_HASH_OFFSET_R_TAG_H,
        MCIPHER_WTAG_VAL_L32, MCIPHER_WTAG_VAL_H32);
    return;
}

/* vmcu */
hi_void iommu_config_vmcu(void)
{
    iommu_tag_set(REG_VMCU_BASE, REG_VMCU_OFFSET_WTAG_L, REG_VMCU_OFFSET_WTAG_H,
        VMCU_WTAG_VAL_L32, VMCU_WTAG_VAL_H32);
    iommu_tag_set(REG_VMCU_BASE, REG_VMCU_OFFSET_RTAG_L, REG_VMCU_OFFSET_RTAG_H,
        VMCU_RTAG_VAL_L32, VMCU_RTAG_VAL_H32);
    return;
}

/* vdh */
hi_void iommu_config_vdh(void)
{
    /* VDH BSP */
    iommu_tag_set(REG_VDH_BSP_BASE, REG_VDH_BSP_OFFSET_WTAG_L, REG_VDH_BSP_OFFSET_WTAG_H,
        VDH_WTAG_VAL_L32, VDH_WTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BSP_BASE, REG_VDH_BSP_OFFSET_RTAG_L, REG_VDH_BSP_OFFSET_RTAG_H,
        VDH_RTAG_VAL_L32, VDH_RTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BSP_BASE, REG_VDH_BSP_OFFSET_SEC_PTB_L, REG_VDH_BSP_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFF0), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BSP_BASE, REG_VDH_BSP_OFFSET_R_ERR_L, REG_VDH_BSP_OFFSET_R_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BSP_BASE, REG_VDH_BSP_OFFSET_W_ERR_L, REG_VDH_BSP_OFFSET_W_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));

    /* vdh bxp0 */
    iommu_tag_set(REG_VDH_BXP0_BASE, REG_VDH_BXP_OFFSET_WTAG_L, REG_VDH_BXP_OFFSET_WTAG_H,
        VDH_WTAG_VAL_L32, VDH_WTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP0_BASE, REG_VDH_BXP_OFFSET_RTAG_L, REG_VDH_BXP_OFFSET_RTAG_H,
        VDH_RTAG_VAL_L32, VDH_RTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP0_BASE, REG_VDH_BXP_OFFSET_SEC_PTB_L, REG_VDH_BXP_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFFF), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP0_BASE, REG_VDH_BXP_OFFSET_R_ERR_L, REG_VDH_BXP_OFFSET_R_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP0_BASE, REG_VDH_BXP_OFFSET_W_ERR_L, REG_VDH_BXP_OFFSET_W_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));
    /* vdh bxp1 */
    iommu_tag_set(REG_VDH_BXP1_BASE, REG_VDH_BXP_OFFSET_WTAG_L, REG_VDH_BXP_OFFSET_WTAG_H,
        VDH_WTAG_VAL_L32, VDH_WTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP1_BASE, REG_VDH_BXP_OFFSET_RTAG_L, REG_VDH_BXP_OFFSET_RTAG_H,
        VDH_RTAG_VAL_L32, VDH_RTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP1_BASE, REG_VDH_BXP_OFFSET_SEC_PTB_L, REG_VDH_BXP_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFFF), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP1_BASE, REG_VDH_BXP_OFFSET_R_ERR_L, REG_VDH_BXP_OFFSET_R_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP1_BASE, REG_VDH_BXP_OFFSET_W_ERR_L, REG_VDH_BXP_OFFSET_W_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));
    /* vdh bxp2 */
    iommu_tag_set(REG_VDH_BXP2_BASE, REG_VDH_BXP_OFFSET_WTAG_L, REG_VDH_BXP_OFFSET_WTAG_H,
        VDH_WTAG_VAL_L32, VDH_WTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP2_BASE, REG_VDH_BXP_OFFSET_RTAG_L, REG_VDH_BXP_OFFSET_RTAG_H,
        VDH_RTAG_VAL_L32, VDH_RTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP2_BASE, REG_VDH_BXP_OFFSET_SEC_PTB_L, REG_VDH_BXP_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFFF), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP2_BASE, REG_VDH_BXP_OFFSET_R_ERR_L, REG_VDH_BXP_OFFSET_R_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP2_BASE, REG_VDH_BXP_OFFSET_W_ERR_L, REG_VDH_BXP_OFFSET_W_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));
    /* vdh bxp3 */
    iommu_tag_set(REG_VDH_BXP3_BASE, REG_VDH_BXP_OFFSET_WTAG_L, REG_VDH_BXP_OFFSET_WTAG_H,
        VDH_WTAG_VAL_L32, VDH_WTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP3_BASE, REG_VDH_BXP_OFFSET_RTAG_L, REG_VDH_BXP_OFFSET_RTAG_H,
        VDH_RTAG_VAL_L32, VDH_RTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP3_BASE, REG_VDH_BXP_OFFSET_SEC_PTB_L, REG_VDH_BXP_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFFF), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP3_BASE, REG_VDH_BXP_OFFSET_R_ERR_L, REG_VDH_BXP_OFFSET_R_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP3_BASE, REG_VDH_BXP_OFFSET_W_ERR_L, REG_VDH_BXP_OFFSET_W_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));

    /* vdh bxp4 */
    iommu_tag_set(REG_VDH_BXP4_BASE, REG_VDH_BXP_OFFSET_WTAG_L, REG_VDH_BXP_OFFSET_WTAG_H,
        VDH_WTAG_VAL_L32, VDH_WTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP4_BASE, REG_VDH_BXP_OFFSET_RTAG_L, REG_VDH_BXP_OFFSET_RTAG_H,
        VDH_RTAG_VAL_L32, VDH_RTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP4_BASE, REG_VDH_BXP_OFFSET_SEC_PTB_L, REG_VDH_BXP_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFFF), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP4_BASE, REG_VDH_BXP_OFFSET_R_ERR_L, REG_VDH_BXP_OFFSET_R_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP4_BASE, REG_VDH_BXP_OFFSET_W_ERR_L, REG_VDH_BXP_OFFSET_W_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));

    /* vdh bxp5 */
    iommu_tag_set(REG_VDH_BXP5_BASE, REG_VDH_BXP_OFFSET_WTAG_L, REG_VDH_BXP_OFFSET_WTAG_H,
        VDH_WTAG_VAL_L32, VDH_WTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP5_BASE, REG_VDH_BXP_OFFSET_RTAG_L, REG_VDH_BXP_OFFSET_RTAG_H,
        VDH_RTAG_VAL_L32, VDH_RTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP5_BASE, REG_VDH_BXP_OFFSET_SEC_PTB_L, REG_VDH_BXP_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFFF), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP5_BASE, REG_VDH_BXP_OFFSET_R_ERR_L, REG_VDH_BXP_OFFSET_R_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP5_BASE, REG_VDH_BXP_OFFSET_W_ERR_L, REG_VDH_BXP_OFFSET_W_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));

    /* vdh bxp6 */
    iommu_tag_set(REG_VDH_BXP6_BASE, REG_VDH_BXP_OFFSET_WTAG_L, REG_VDH_BXP_OFFSET_WTAG_H,
        VDH_WTAG_VAL_L32, VDH_WTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP6_BASE, REG_VDH_BXP_OFFSET_RTAG_L, REG_VDH_BXP_OFFSET_RTAG_H,
        VDH_RTAG_VAL_L32, VDH_RTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP6_BASE, REG_VDH_BXP_OFFSET_SEC_PTB_L, REG_VDH_BXP_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFFF), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP6_BASE, REG_VDH_BXP_OFFSET_R_ERR_L, REG_VDH_BXP_OFFSET_R_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP6_BASE, REG_VDH_BXP_OFFSET_W_ERR_L, REG_VDH_BXP_OFFSET_W_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));

    /* vdh bxp7 */
    iommu_tag_set(REG_VDH_BXP7_BASE, REG_VDH_BXP_OFFSET_WTAG_L, REG_VDH_BXP_OFFSET_WTAG_H,
        VDH_WTAG_VAL_L32, VDH_WTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP7_BASE, REG_VDH_BXP_OFFSET_RTAG_L, REG_VDH_BXP_OFFSET_RTAG_H,
        VDH_RTAG_VAL_L32, VDH_RTAG_VAL_H32);
    iommu_tag_set(REG_VDH_BXP7_BASE, REG_VDH_BXP_OFFSET_SEC_PTB_L, REG_VDH_BXP_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFFF), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP7_BASE, REG_VDH_BXP_OFFSET_R_ERR_L, REG_VDH_BXP_OFFSET_R_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDH_BXP7_BASE, REG_VDH_BXP_OFFSET_W_ERR_L, REG_VDH_BXP_OFFSET_W_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));
    return;
}

/* vpss */
hi_void iommu_config_vpss(void)
{
    /* vpss0 */
    iommu_tag_set_onereg(REG_VPSS0_SAFE_BASE, 0, VPSS0_VALUE_SCR);

    iommu_tag_set(REG_VPSS0_SAFE_BASE, REG_VPSS0_OFFSET_SCR, REG_VPSS0_OFFSET_LP_CTRL,
        VPSS0_VALUE_SCR, VPSS0_VALUE_LP_CTRL);
    iommu_tag_set(REG_VPSS0_SAFE_BASE, REG_VPSS0_OFFSET_MEM_SPEEDCTRL, REG_VPSS0_OFFSET_INTMASK,
        VPSS0_VALUE_MEM_SPEEDCTRL, VPSS0_VALUE_INTMASK);
    iommu_tag_set(REG_VPSS0_SAFE_BASE, REG_VPSS0_OFFSET_STAG_RD_CTRL, REG_VPSS0_OFFSET_STAG_WR_CTRL,
        VPSS0_VALUE_STAG_RD_CTRL, VPSS0_VALUE_STAG_WR_CTRL);
    iommu_tag_set(REG_VPSS0_SAFE_BASE, REG_VPSS0_OFFSET_STAG_RD_AC0, REG_VPSS0_OFFSET_STAG_RD_AC1,
        VPSS0_VALUE_STAG_RD_AC0, VPSS0_VALUE_STAG_RD_AC1);
    iommu_tag_set(REG_VPSS0_SAFE_BASE, REG_VPSS0_OFFSET_STAG_WR_AC0, REG_VPSS0_OFFSET_STAG_WR_AC1,
        VPSS0_VALUE_STAG_WR_AC0, VPSS0_VALUE_STAG_WR_AC1);

    iommu_tag_set(REG_VPSS0_SAFE_BASE, REG_VPSS0_OFFSET_SCB_TTBR, REG_VPSS0_OFFSET_SCB_TTBR_H,
                  (g_sec_pgtbl_addr & 0XFFFFFFF0), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VPSS0_SAFE_BASE, REG_VPSS0_OFFSET_RD_ERR_L, REG_VPSS0_OFFSET_RD_ERR_H,
                  (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VPSS0_SAFE_BASE, REG_VPSS0_OFFSET_WR_ERR_L, REG_VPSS0_OFFSET_WR_ERR_H,
                  (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));
    /* global smmu ctrl */
    iommu_tag_set_onereg(REG_VPSS0_MAC_SMMUR_CTRL_BASE, REG_VPSS0_OFFSET_MAC_SMMUR_CTRL, VPSS0_VALUE_MAC_SMMUR_CTRL);

    return;
}

static hi_void iommu_config_hifb(void)
{
    hi_u32 value;

    writel(HIFB_VALUE_SMMU_BYPASS, REG_HIFB_SMMU_BASE + REG_HIFB_OFFSET_G0_SMMU_BYPASS);
    writel(HIFB_VALUE_SMMU_BYPASS, REG_HIFB_SMMU_BASE + REG_HIFB_OFFSET_G1_SMMU_BYPASS);
    writel(HIFB_VALUE_SMMU_BYPASS, REG_HIFB_SMMU_BASE + REG_HIFB_OFFSET_G2_SMMU_BYPASS);
    writel(HIFB_VALUE_SMMU_BYPASS, REG_HIFB_SMMU_BASE + REG_HIFB_OFFSET_G3_SMMU_BYPASS);

    value = readl(REG_TEE_VDP_OUT_CTRL0);
    value |= TEE_VDP_OUT_CTRL0_MASK;
    writel(value, REG_TEE_VDP_OUT_CTRL0);
    value = readl(REG_TEE_TZEN_CTRL);
    value |= TEE_TZEN_CTRL_MASK;
    writel(value, REG_TEE_TZEN_CTRL);
}

/* vdp */
hi_void iommu_config_vdp(void)
{
    (*(volatile u32 *)(REG_VDP0_MMU_BASE)) = VDP_VALUE_SCR;
    (*(volatile u32 *)(REG_VDP_REGION_MMU_BASE)) = VDP_VALUE_SCR;
    iommu_tag_set(REG_VDP0_MMU_BASE, REG_VDP_OFFSET_SCR, REG_VDP_OFFSET_LP_CTRL, VDP_VALUE_SCR, VDP_VALUE_LP_CTRL);
    iommu_tag_set(REG_VDP0_MMU_BASE, REG_VDP_OFFSET_MEM_SPEEDCTRL, REG_VDP_OFFSET_INTMASK,
        VDP_VALUE_MEM_SPEEDCTRL, VDP_VALUE_INTMASK);
    iommu_tag_set(REG_VDP0_MMU_BASE, REG_VDP_OFFSET_STAG_RDCTL, REG_VDP_OFFSET_STAG_WRCTL,
        VDP_VALUE_STAG_RDCTL, VDP_VALUE_STAG_WRCTL);
    iommu_tag_set(REG_VDP0_MMU_BASE, REG_VDP_OFFSET_STAG_RDAC0, REG_VDP_OFFSET_STAG_RDAC1,
        VDP_VALUE_STAG_RDAC0, VDP_VALUE_STAG_RDAC1);
    iommu_tag_set(REG_VDP0_MMU_BASE, REG_VDP_OFFSET_STAG_WRAC0, REG_VDP_OFFSET_STAG_WRAC1,
        VDP_VALUE_STAG_WRAC0, VDP_VALUE_STAG_WRAC1);
    iommu_tag_set(REG_VDP0_MMU_BASE, REG_VDP_OFFSET_SEC_PTB_L, REG_VDP_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFF0), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDP0_MMU_BASE, REG_VDP_OFFSET_RD_ERR_L, REG_VDP_OFFSET_RD_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDP0_MMU_BASE, REG_VDP_OFFSET_WR_ERR_L, REG_VDP_OFFSET_WR_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDP_VID_READ_CTRL_BASE, REG_VDP_OFFSET_SMMU_BYPASS, HI_NULL,
        VDP_VALUE_VID_SMMU_BYPASS, HI_NULL);
    iommu_tag_set(REG_VDP_VID1_READ_CTRL_BASE, REG_VDP_OFFSET_SMMU_BYPASS, HI_NULL,
        VDP_VALUE_VID_SMMU_BYPASS, HI_NULL);
    iommu_tag_set(REG_VDP_VID3_READ_CTRL_BASE, REG_VDP_OFFSET_SMMU_BYPASS, HI_NULL,
        VDP_VALUE_VID_SMMU_BYPASS, HI_NULL);

    (*(volatile u32 *)(REG_VDP1_MMU_BASE)) = VDP_VALUE_SCR;
    iommu_tag_set(REG_VDP1_MMU_BASE, REG_VDP_OFFSET_SCR, REG_VDP_OFFSET_LP_CTRL, VDP_VALUE_SCR, VDP_VALUE_LP_CTRL);
    iommu_tag_set(REG_VDP1_MMU_BASE, REG_VDP_OFFSET_MEM_SPEEDCTRL, REG_VDP_OFFSET_INTMASK,
        VDP_VALUE_MEM_SPEEDCTRL, VDP_VALUE_INTMASK);
    iommu_tag_set(REG_VDP1_MMU_BASE, REG_VDP_OFFSET_STAG_RDCTL, REG_VDP_OFFSET_STAG_WRCTL,
        VDP_VALUE_STAG_RDCTL, VDP_VALUE_STAG_WRCTL);
    iommu_tag_set(REG_VDP1_MMU_BASE, REG_VDP_OFFSET_STAG_RDAC0, REG_VDP_OFFSET_STAG_RDAC1,
        VDP_VALUE_STAG_RDAC0, VDP_VALUE_STAG_RDAC1);
    iommu_tag_set(REG_VDP1_MMU_BASE, REG_VDP_OFFSET_STAG_WRAC0, REG_VDP_OFFSET_STAG_WRAC1,
        VDP_VALUE_STAG_WRAC0, VDP_VALUE_STAG_WRAC1);
    iommu_tag_set(REG_VDP1_MMU_BASE, REG_VDP_OFFSET_SEC_PTB_L, REG_VDP_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFF0), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDP1_MMU_BASE, REG_VDP_OFFSET_RD_ERR_L, REG_VDP_OFFSET_RD_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDP1_MMU_BASE, REG_VDP_OFFSET_WR_ERR_L, REG_VDP_OFFSET_WR_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));

    (*(volatile u32 *)(REG_VDP2_MMU_BASE)) = VDP_VALUE_SCR;
    iommu_tag_set(REG_VDP2_MMU_BASE, REG_VDP_OFFSET_SCR, REG_VDP_OFFSET_LP_CTRL, VDP_VALUE_SCR, VDP_VALUE_LP_CTRL);
    iommu_tag_set(REG_VDP2_MMU_BASE, REG_VDP_OFFSET_MEM_SPEEDCTRL, REG_VDP_OFFSET_INTMASK,
        VDP_VALUE_MEM_SPEEDCTRL, VDP_VALUE_INTMASK);
    iommu_tag_set(REG_VDP2_MMU_BASE, REG_VDP_OFFSET_STAG_RDCTL, REG_VDP_OFFSET_STAG_WRCTL,
        VDP_VALUE_STAG_RDCTL, VDP_VALUE_STAG_WRCTL);
    iommu_tag_set(REG_VDP2_MMU_BASE, REG_VDP_OFFSET_STAG_RDAC0, REG_VDP_OFFSET_STAG_RDAC1,
        VDP_VALUE_STAG_RDAC0, VDP_VALUE_STAG_RDAC1);
    iommu_tag_set(REG_VDP2_MMU_BASE, REG_VDP_OFFSET_STAG_WRAC0, REG_VDP_OFFSET_STAG_WRAC1,
        VDP_VALUE_STAG_WRAC0, VDP_VALUE_STAG_WRAC1);
    iommu_tag_set(REG_VDP2_MMU_BASE, REG_VDP_OFFSET_SEC_PTB_L, REG_VDP_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFF0), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDP2_MMU_BASE, REG_VDP_OFFSET_RD_ERR_L, REG_VDP_OFFSET_RD_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_VDP2_MMU_BASE, REG_VDP_OFFSET_WR_ERR_L, REG_VDP_OFFSET_WR_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));

    iommu_config_hifb();

    return;
}

hi_void iommu_config_gfx2d(void)
{
    writel(0, REG_GFX2D_SMMU_BYPASS_CTRL);
    writel(0, REG_GFX2D_SMMU_BASE);

    iommu_tag_set(REG_GFX2D_SMMU_BASE, REG_GFX2D_OFFSET_RTAG_CTL, REG_GFX2D_OFFSET_WTAG_CTL,
        GFX2D_VALUE_STAG_RDCTL, GFX2D_VALUE_STAG_WRCTL);
    iommu_tag_set(REG_GFX2D_SMMU_BASE, REG_GFX2D_OFFSET_RTAG_L, REG_GFX2D_OFFSET_RTAG_H,
        GFX2D_VALUE_STAG_RDAC0, GFX2D_VALUE_STAG_RDAC1);
    iommu_tag_set(REG_GFX2D_SMMU_BASE, REG_GFX2D_OFFSET_WTAG_L, REG_GFX2D_OFFSET_WTAG_H,
        GFX2D_VALUE_STAG_WRAC0, GFX2D_VALUE_STAG_WRAC1);

    iommu_tag_set(REG_GFX2D_SMMU_BASE, REG_GFX2D_OFFSET_SEC_PTB_L, REG_GFX2D_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFFF), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_GFX2D_SMMU_BASE, REG_GFX2D_OFFSET_R_ERR_L, REG_GFX2D_OFFSET_R_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_GFX2D_SMMU_BASE, REG_GFX2D_OFFSET_W_ERR_L, REG_GFX2D_OFFSET_W_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));
    return;
}

hi_void iommu_config_venc(void)
{
    unsigned int value;
    const unsigned int crg_base = GPU_CRG_REG_ADDR_BASE;

    /* open vedu smmu cken */
    value = readl(crg_base);
    value |= (1 << VEDU_SMMU_CKEN_ADDR_OFFSET);
    writel(value, crg_base);

    /* reset vedu smmu */
    value |= (1 << VEDU_SMMU_SRST_ADDR_OFFSET);
    writel(value, crg_base);

    value &= ~(1 << VEDU_SMMU_SRST_ADDR_OFFSET);
    writel(value, crg_base);

    /* config vedu smmu glb_bypass to 0 */
    writel(0, VEDU_SMMU_REG_ADDR_BASE);

    return;
}

hi_void iommu_config_vi(void)
{
    writel(0, VICAP0_SMMU_REG_ADDR_BASE);
    writel(0, VICAP1_SMMU_REG_ADDR_BASE);
}

static hi_void iommu_config_jpeg(void)
{
    unsigned int value;

    value = readl(REG_TEE_CTRL_BASE + REG_JPEG_OFFSET_TZEN_CTRL);
    value |= 0 << SHIFT_FOR_HIGH_16;

    writel(value, REG_TEE_CTRL_BASE + REG_JPEG_OFFSET_TZEN_CTRL);

    writel(REG_JPEG_VALUE_SMMU_ALLOW, REG_JPEG_MMU_BASE + REG_JPEG_OFFSET_STAG_RD_ACCESS0);
    writel(REG_JPEG_VALUE_SMMU_ALLOW, REG_JPEG_MMU_BASE + REG_JPEG_OFFSET_STAG_RD_ACCESS1);
    writel(REG_JPEG_VALUE_SMMU_ALLOW, REG_JPEG_MMU_BASE + REG_JPEG_OFFSET_STAG_WR_ACCESS0);
    writel(REG_JPEG_VALUE_SMMU_ALLOW, REG_JPEG_MMU_BASE + REG_JPEG_OFFSET_STAG_WR_ACCESS1);
    writel(REG_JPEG_VALUE_SMMU_ENABLE, REG_JPEG_MMU_BASE + REG_JPEG_OFFSET_STAG_RD_CTRL);
    writel(REG_JPEG_VALUE_SMMU_ENABLE, REG_JPEG_MMU_BASE + REG_JPEG_OFFSET_STAG_WR_CTRL);
    writel(REG_JPEG_VALUE_SMMU_DISABLE, REG_JPEG_MMU_BASE + REG_JPEG_OFFSET_SMMU_SCR);

    iommu_tag_set(REG_JPEG_MMU_BASE, REG_JPEG_OFFSET_SCB_TTBR_L, REG_JPEG_OFFSET_SCB_TTBR_H,
        (g_sec_pgtbl_addr & 0XFFFFFFFF), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_JPEG_MMU_BASE, REG_JPEG_OFFSET_ERR_RDADDR_L, REG_JPEG_OFFSET_ERR_RDADDR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_JPEG_MMU_BASE, REG_JPEG_OFFSET_ERR_WRADDR_L, REG_JPEG_OFFSET_ERR_WRADDR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));
}

static hi_void iommu_config_jpge(void)
{
    writel(0, REG_JPGE_SMMU_BASE);

    iommu_tag_set(REG_JPGE_SMMU_BASE, REG_JPGE_OFFSET_RTAG_CTL, REG_JPGE_OFFSET_WTAG_CTL,
        JPGE_VALUE_STAG_RDCTL, JPGE_VALUE_STAG_WRCTL);
    iommu_tag_set(REG_JPGE_SMMU_BASE, REG_JPGE_OFFSET_RTAG_L, REG_JPGE_OFFSET_RTAG_H,
        JPGE_VALUE_STAG_RDAC0, JPGE_VALUE_STAG_RDAC1);
    iommu_tag_set(REG_JPGE_SMMU_BASE, REG_JPGE_OFFSET_WTAG_L, REG_JPGE_OFFSET_WTAG_H,
        JPGE_VALUE_STAG_WRAC0, JPGE_VALUE_STAG_WRAC1);

    iommu_tag_set(REG_JPGE_SMMU_BASE, REG_JPGE_OFFSET_SEC_PTB_L, REG_JPGE_OFFSET_SEC_PTB_H,
        (g_sec_pgtbl_addr & 0XFFFFFFFF), (g_sec_pgtbl_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_JPGE_SMMU_BASE, REG_JPGE_OFFSET_R_ERR_L, REG_JPGE_OFFSET_R_ERR_H,
        (g_read_err_addr & 0XFFFFFFFF), (g_read_err_addr >> SHIFT_FOR_HIGH_32));
    iommu_tag_set(REG_JPGE_SMMU_BASE, REG_JPGE_OFFSET_W_ERR_L, REG_JPGE_OFFSET_W_ERR_H,
        (g_write_err_addr & 0XFFFFFFFF), (g_write_err_addr >> SHIFT_FOR_HIGH_32));
    return;
}

hi_void iommu_config_gpu(void)
{
    unsigned int value;
    const unsigned int crg_base = GPU_CRG_REG_ADDR_BASE;
    const unsigned int tee_base = GPU_TEE_REG_ADDR_BASE;
    const unsigned int mmu_base = GPU_MMU_REG_ADDR_BASE;

    /* enable secure crg */
    value = readl(crg_base);
    value |= (1 << GPU_CRG_REG_OFFSET_SECURE_ENABLE);
    writel(value, crg_base);

    value &= ~(1 << GPU_CRG_REG_OFFSET_SECURE_ENABLE);
    writel(value, crg_base);

    /* enable gpu tee */
    value = readl(tee_base);
    value |= (1 << GPU_TEE_REG_TZ_ENABLE);
    writel(value, tee_base);

    /* enable global bypass */
    writel(0, mmu_base + GPU_MMU_REG_ADDR_SCR);

    /* configure smmu page table base addr */
    writel(g_sec_pgtbl_addr, mmu_base + GPU_MMU_REG_ADDR_SCB_TTBR);
    writel(0x0,              mmu_base + GPU_MMU_REG_ADDR_SCB_TTBR_H);

    /* config gpu secure read ability */
    writel(0x1, mmu_base + GPU_MMU_REG_ADDR_STAG_RD_CTRL);

    value = readl(mmu_base + GPU_MMU_REG_ADDR_STAG_RD_ACCESS0);
    value |= (1 << GPU_MMU_REG_OFFSET_SECURE_R_ENABLE_GPU_ONLY);
    value |= (1 << GPU_MMU_REG_OFFSET_SECURE_R_ENABLE);
    writel(value, mmu_base + GPU_MMU_REG_ADDR_STAG_RD_ACCESS0);

    value = readl(mmu_base + GPU_MMU_REG_ADDR_STAG_RD_ACCESS1);
    writel(value, mmu_base + GPU_MMU_REG_ADDR_STAG_RD_ACCESS1);

    /* config gpu secure write ability */
    writel(0x1, mmu_base + GPU_MMU_REG_ADDR_STAG_WR_CTRL);

    value = readl(mmu_base + GPU_MMU_REG_ADDR_STAG_WR_ACCESS0);
    value |= (1 << GPU_MMU_REG_OFFSET_SECURE_W_ENABLE_GPU_ONLY);
    writel(value, mmu_base + GPU_MMU_REG_ADDR_STAG_WR_ACCESS0);

    value = readl(mmu_base + GPU_MMU_REG_ADDR_STAG_WR_ACCESS1);
    value |= (1 << GPU_MMU_REG_OFFSET_SECURE_W_ENABLE);
    writel(value, mmu_base + GPU_MMU_REG_ADDR_STAG_WR_ACCESS1);

    return;
}

static ssm_iommu_cfg_map g_iommu_cfg_map[] = {
    {LOGIC_MOD_ID_DEMUX, iommu_config_demux},
    {LOGIC_MOD_ID_TSCIPHER, iommu_config_tscipher},
    {LOGIC_MOD_ID_CIPHER, iommu_config_mcipher},
    {LOGIC_MOD_ID_VMCU, iommu_config_vmcu},
    {LOGIC_MOD_ID_VPSS, iommu_config_vpss},
    {LOGIC_MOD_ID_VDH, iommu_config_vdh},
    {LOGIC_MOD_ID_VDP, iommu_config_vdp},
    {LOGIC_MOD_ID_HWC, iommu_config_gfx2d},
    {LOGIC_MOD_ID_GPU, iommu_config_gpu},
    {LOGIC_MOD_ID_VI, iommu_config_vi},
    {LOGIC_MOD_ID_VENC, iommu_config_venc},
    {LOGIC_MOD_ID_JPEG_DEC, iommu_config_jpeg},
    {LOGIC_MOD_ID_JPEG_ENC, iommu_config_jpge},
};

hi_s32 iommu_sec_config(hi_tee_logic_mod_id mod_id)
{
    hi_u32 i;

    for (i = 0; i < sizeof(g_iommu_cfg_map) / sizeof(g_iommu_cfg_map[0]); i++) {
        if (mod_id != g_iommu_cfg_map[i].mod_id) {
            continue;
        }

        g_iommu_cfg_map[i].iommu_cfg_handler();
        break;
    }

    if (i >= sizeof(g_iommu_cfg_map) / sizeof(g_iommu_cfg_map[0])) {
        hi_tee_drv_hal_printf("cannot find mod to init iommu reg! mod_id: %d\n", mod_id);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_void iommu_tag_init(void)
{
    hi_s32 ret = HI_FAILURE;

    if (g_read_err_addr == 0 || g_write_err_addr == 0 || g_sec_pgtbl_addr == 0) {
        ret = hi_tee_drv_smmu_get_pgtinfo(&g_read_err_addr, &g_write_err_addr, &g_sec_pgtbl_addr);
        if (ret != HI_SUCCESS) {
            hi_tee_drv_hal_printf("cannot get pgtinfo-%d\n", __LINE__);
        }
    }

    return;
}

hi_void iommu_get_pgt_addr(hi_u64 *pgt_addr)
{
    if (pgt_addr == HI_NULL) {
        hi_tee_drv_hal_printf("invalid param pointer-%s, %d\n", __func__, __LINE__);
    }

    *pgt_addr = g_sec_pgtbl_addr;

    return;
}


