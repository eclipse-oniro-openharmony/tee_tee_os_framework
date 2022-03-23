/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: decoder
 * Author: sdk
 * Create: 2019-04-22
 */

#include "tee_drv_vfmw.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_drv_mem.h"
#include "hi_type_dev.h"
#include "tee_drv_vfmw_sign.h"

#define MCU_EXEC_ADDR_SRG_OFS  0x0
#define MCU_ITCM_START_REG_OSF 0x08
#define MCU_ITCM_END_REG_OSF   0x0C
#define MCU_DTCM_START_REG_OSF 0x10
#define MCU_DTCM_END_REG_OSF   0x14
#define MCU_AXI_START_REG_OSF  0x18
#define MCU_AXI_END_REG_OSF    0x1C
#define MCU_AHB_START_REG_OSF  0x20
#define MCU_AHB_END_REG_OSF    0x24
#define MCU_WFI_REG_OFS        0x28
#define MCU_WFI_BIT            0
#define MCU_WAIT_REG_OFS       0x2C
#define MCU_CLK_CFG            0x38
#define MCU_RST_REG_OFS        0x3C
#define MCU_BIN_RESERVE_OFFSET 12

#define MCU_COMMON_STA_OFS     0x24

#define ITCM_BASE_ADDR         0x01280000
#define ITCM_BASE_ADDR_IN_MDC  0x00810000
#define ITCM_CODE_LEN          0x8000 /*  32K  */
#define DTCM_BASE_ADDR         0x01288000
#define DTCM_BASE_ADDR_IN_MDC  0x00828000
#define DTCM_DATA_LEN          0x8000 /*  32K  */

#define wr_reg(base, reg, dat) \
    do {                                                      \
        *((volatile hi_u32 *)((hi_u8 *)(base) + (reg))) = dat; \
    } while (0)
#define rd_reg(base, reg, dat)                                \
    do {                                                      \
        dat = *((volatile hi_u32 *)((hi_u8 *)(base) + (reg))); \
    } while (0)

#define mdc_reg_map(phy, len)  (hi_u8 *)(phy)
#define mdc_reg_unmap(vir)
#define mdc_align(val, align) ((val) & (~((align)-1)))

typedef struct {
    hi_u8 *src_bin;
    hi_u8 *dst_bin;
    hi_u32 bin_len;
} vfmw_ctx;

static vfmw_ctx g_vfmw_ctx;

static vfmw_ctx *vfmw_get_ctx(hi_void)
{
    return &g_vfmw_ctx;
}

static hi_void vfmw_config_mdc(hi_u8 *mdc_reg_virt_addr, hi_u8 *mdc_sta_reg_virt_addr)
{
    wr_reg(mdc_reg_virt_addr, MCU_ITCM_START_REG_OSF, ITCM_BASE_ADDR_IN_MDC); /* CFG ITCM START ADDR */
    wr_reg(mdc_reg_virt_addr, MCU_ITCM_END_REG_OSF,
        ITCM_BASE_ADDR_IN_MDC + ITCM_CODE_LEN - 1); /* CFG ITCM END ADDR */

    wr_reg(mdc_reg_virt_addr, MCU_DTCM_START_REG_OSF, DTCM_BASE_ADDR_IN_MDC); /* CFG DTCM START ADDR */
    wr_reg(mdc_reg_virt_addr,
        MCU_DTCM_END_REG_OSF, DTCM_BASE_ADDR_IN_MDC + DTCM_DATA_LEN - 1); /* CFG DTCM END ADDR */

    wr_reg(mdc_reg_virt_addr, MCU_AXI_START_REG_OSF, 0x10000000); /* CFG AXI START ADDR */
    wr_reg(mdc_reg_virt_addr, MCU_AXI_END_REG_OSF, 0xFFFFFFFF); /* CFG AXI END ADDR */

    wr_reg(mdc_reg_virt_addr, MCU_AHB_START_REG_OSF, 0x830000); /* CFG AHB START ADDR */
    wr_reg(mdc_reg_virt_addr, MCU_AHB_END_REG_OSF, 0x0FFFFFFF); /* CFG AHB END ADDR */

    wr_reg(mdc_reg_virt_addr, 0x00, MCU_DAT_BASE_ADDR); /* CFG MDC START ADDR */

    wr_reg(mdc_reg_virt_addr, MCU_CLK_CFG, 0x1FF); /* Open MCU Clock */

    wr_reg(mdc_reg_virt_addr, MCU_RST_REG_OFS, 1); /* RESET DERESET MCU */

    wr_reg(mdc_sta_reg_virt_addr, MCU_COMMON_STA_OFS, 0); /* INIT MDC COMMON STATE POS REG */

    wr_reg(mdc_reg_virt_addr, MCU_RST_REG_OFS, 0); /* DERESET ALL MODULE */

    wr_reg(mdc_reg_virt_addr, MCU_WAIT_REG_OFS, 0); /* CLEAR WAIT */

    return;
}

static hi_s32 vfmw_copy_bin(hi_u8 *dst_bin, hi_u32 dst_len, hi_u8 *src_bin, hi_u32 src_len)
{
    if (memcpy_s(dst_bin, dst_len, src_bin, src_len) != EOK) {
        hi_tee_drv_hal_printf("%s memcpy_s %p to %p length 0x%x failed\n",
            __func__, src_bin, dst_bin, src_len);
        return HI_FAILURE;
    }

    hi_tee_drv_hal_dcache_flush(dst_bin, dst_len);

    return HI_SUCCESS;
}

static hi_s32 vfmw_cpy_config_mdc(hi_u8 *dst_bin, hi_u8 *src_bin, hi_u32 copy_len)
{
    hi_s32 ret = HI_FAILURE;
    hi_u8 *mdc_reg_virt_addr = HI_NULL;
    hi_u8 *mdc_sta_reg_virt_addr = HI_NULL;

    mdc_reg_virt_addr = mdc_reg_map(REG_BASE_MDC0CFG, REG_SIZE_MDC0CFG);
    if (mdc_reg_virt_addr == HI_NULL) {
        hi_tee_drv_hal_printf("%s map mdc_reg_virt_addr Failed\n", __func__);
        goto clean_up0;
    }

    wr_reg(mdc_reg_virt_addr, MCU_RST_REG_OFS, 0x1BF); /* reset all modules unless mtimer to count */

    if (vfmw_copy_bin(dst_bin, copy_len, src_bin, copy_len) != HI_SUCCESS) {
        hi_tee_drv_hal_printf("%s vfmw_copy_bin Failed\n", __func__);
        goto clean_up1;
    }

    mdc_sta_reg_virt_addr = mdc_reg_map(REG_BASE_MDC0STA, REG_SIZE_MDC0STA);
    if (mdc_sta_reg_virt_addr == HI_NULL) {
        hi_tee_drv_hal_printf("%s map mdc_sta_reg_virt_addr Failed\n", __func__);
        goto clean_up1;
    }

    vfmw_config_mdc(mdc_reg_virt_addr, mdc_sta_reg_virt_addr);

    ret = HI_SUCCESS;

    mdc_reg_unmap(mdc_sta_reg_virt_addr);
clean_up1:
    mdc_reg_unmap(mdc_reg_virt_addr);
clean_up0:

    return ret;
}

static hi_s32 vfmw_load_mdc(hi_u32 length)
{
    vfmw_ctx *ctx = vfmw_get_ctx();

    if (length < VFMW_IMAGE_MIN_LEN || length > VFMW_IMAGE_MAX_LEN) {
        hi_tee_drv_hal_printf("%s check para bin_len %d Failed\n", __func__, length);
        return HI_FAILURE;
    }

    ctx->bin_len = length;
    ctx->src_bin = hi_tee_drv_hal_remap(MCU_DAT_AFT_DECRYPT_ADDR, length, TRUE, TRUE);
    if (ctx->src_bin == HI_NULL) {
        hi_tee_drv_hal_printf("%s remap MCU_DAT_SRC_ADDR failed\n", __func__);
        goto err0;
    }

    ctx->dst_bin = hi_tee_drv_hal_remap(MCU_DAT_BASE_ADDR, length, TRUE, TRUE);
    if (ctx->dst_bin == HI_NULL) {
        hi_tee_drv_hal_printf("%s remap MCU_DAT_BASE_ADDR failed\n", __func__);
        goto err1;
    }

    if (vfmw_cpy_config_mdc(ctx->dst_bin, ctx->src_bin, length) != HI_SUCCESS) {
        hi_tee_drv_hal_printf("%s vfmw_map_config_mdc Failed\n", __func__);
        goto err2;
    }

    return HI_SUCCESS;
err2:
    hi_tee_drv_hal_unmap(ctx->dst_bin, length);
    ctx->dst_bin = HI_NULL;
err1:
    hi_tee_drv_hal_unmap(ctx->src_bin, length);
    ctx->src_bin = HI_NULL;
err0:

    return HI_FAILURE;
}

static hi_s32 vfmw_reload_mdc(hi_void)
{
    vfmw_ctx *ctx = vfmw_get_ctx();
    hi_u32 text_len, copy_ofs, copy_len;

    if (ctx->src_bin == HI_NULL ||
        ctx->dst_bin == HI_NULL ||
        ctx->bin_len < VFMW_IMAGE_MIN_LEN ||
        ctx->bin_len > VFMW_IMAGE_MAX_LEN) {
        hi_tee_drv_hal_printf("%s check para bin_len %d Failed\n", __func__, ctx->bin_len);
        return HI_FAILURE;
    }

    text_len = *(volatile hi_u32 *)(ctx->src_bin + MCU_BIN_RESERVE_OFFSET);
    copy_ofs = mdc_align(text_len, 0x1000); /* align 4k */
    copy_len = ctx->bin_len - copy_ofs;

    if (vfmw_cpy_config_mdc(ctx->dst_bin + copy_ofs, ctx->src_bin + copy_ofs, copy_len) != HI_SUCCESS) {
        hi_tee_drv_hal_printf("%s vfmw_map_config_mdc Failed\n", __func__);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 vfmw_unload_mdc(hi_u32 length, hi_u32 option)
{
    hi_s32 ret = HI_FAILURE;
    hi_u8 *mdc_reg_virt_addr = HI_NULL;
    hi_u8 *mdc_sta_reg_virt_addr = HI_NULL;
    hi_u32 suspend = option;
    vfmw_ctx *ctx = vfmw_get_ctx();

    HI_UNUSED(length);
    mdc_reg_virt_addr = mdc_reg_map(REG_BASE_MDC0CFG, REG_SIZE_MDC0CFG);
    if (mdc_reg_virt_addr == HI_NULL) {
        hi_tee_drv_hal_printf("%s map mdc_reg_virt_addr Failed\n", __func__);
        goto clean_up0;
    }

    wr_reg(mdc_reg_virt_addr, MCU_RST_REG_OFS, 0x1FF); /* RESET MDC */

    wr_reg(mdc_reg_virt_addr, MCU_CLK_CFG, 0); /* Close MCU Clock */

    mdc_sta_reg_virt_addr = mdc_reg_map(REG_BASE_MDC0STA, REG_SIZE_MDC0STA);
    if (mdc_sta_reg_virt_addr == HI_NULL) {
        hi_tee_drv_hal_printf("%s map mdc_sta_reg_virt_addr Failed\n", __func__);
        goto clean_up1;
    }

    wr_reg(mdc_sta_reg_virt_addr, MCU_COMMON_STA_OFS, 0xFFFFFFFF); /* MARK MDC STATE */

    if (suspend == 0) { /* 0: unload ko */
        hi_tee_drv_hal_unmap(ctx->src_bin, ctx->bin_len);
        ctx->src_bin = HI_NULL;
        hi_tee_drv_hal_unmap(ctx->dst_bin, ctx->bin_len);
        ctx->dst_bin = HI_NULL;
    }

    ret = HI_SUCCESS;

    mdc_reg_unmap(mdc_sta_reg_virt_addr);
clean_up1:
    mdc_reg_unmap(mdc_reg_virt_addr);
clean_up0:

    return ret;
}

hi_s32 vfmw_syscall(hi_s32 swi_id, TSK_REGS_S *regs, hi_u64 permissions)
{
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_VFMW_LOAD, permissions, GENERAL_GROUP_PERMISSION)
            regs->r0 = vfmw_load_mdc(regs->r1);  /* return value for api */
            SYSCALL_END
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_VFMW_RELOAD, permissions, GENERAL_GROUP_PERMISSION)
            regs->r0 = vfmw_reload_mdc();  /* return value for api */
            SYSCALL_END
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_VFMW_UNLOAD, permissions, GENERAL_GROUP_PERMISSION)
            regs->r0 = vfmw_unload_mdc(regs->r1, regs->r0);  /* return value for api */
            SYSCALL_END
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_VFMW_CMD, permissions, GENERAL_GROUP_PERMISSION)
            regs->r0 = tee_drv_vfmw_cmd_ioctl(regs->r0, regs->r1);
            SYSCALL_END
        default:
            return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_tee_drv_hal_driver_init_late(drv_vfmw, 0, NULL, vfmw_syscall, NULL, NULL);
