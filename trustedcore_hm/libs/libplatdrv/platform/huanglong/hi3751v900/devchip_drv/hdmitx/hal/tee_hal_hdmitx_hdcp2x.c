/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hdmi hal level hdcp2x source file.
 * Author: Hisilicon multimedia interface software group
 * Create: 2019-11-15
 */

#include "hi_log.h"
#include "tee_hal_hdmitx_io.h"
#include "tee_hal_hdmitx_hdcp2x.h"
#include "tee_hal_hdmitx_hdcp2x_mcu.h"
#include "tee_drv_hdmitx.h"
#include "tee_hal_hdmitx_reg_hdcp.h"

#define HDCP2X_BASE_ADDR_MCU_PRAM   0x10000
#define HDCP2X_BASE_ADDR_MCU_DRAM   0x18000
#define HDCP2X_MCU_DRAM_SIZE        (4 * 1024)
#define HDCP2X_RECVID_VILIDNUM_ADDR 0xA80
#define HDCP2X_RECVID_LIST_ADDR     0xA81
#define HDCP2X_RECVID_ADDR          0xB20
#define HDCP2X_OFFSET_HDCP2XVERSION 0x50
#define DRAM_ADDR_RECVID_VALIDNUM   0xA80
#define DRAM_ADDR_RECVID_LIST       (DRAM_ADDR_RECVID_VALIDNUM + 0x1)
#define RETRY_CNT                   5
#define HDCP2X_HW_VERION            0x100
#define hdcp2x_dram_read(hdmi_reg, offset) hdmi_readl(hdmi_reg, HDCP2X_BASE_ADDR_MCU_DRAM + (offset) * 4)

#define HDCP2X_RECVID_SIZE          5
#define HDCP2X_DEVICE_MAX_NUM       31
#define HDCP2X_RECVID_LIST_MAX_SIZE (HDCP2X_DEVICE_MAX_NUM * HDCP2X_RECVID_SIZE)

hi_s32 hdcp2x_load_mcu_code(struct tee_hdmitx *tee)
{
    hi_s32 ret;
    hi_u32 i, data, max_write_times;
    hi_u32 *code = g_8051_mcu_code;

    if (tee == HI_NULL || tee->pwd_regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    ret = HI_SUCCESS;
    for (i = 0; i < sizeof(g_8051_mcu_code) / sizeof(g_8051_mcu_code[0]); i++) {
        for (max_write_times = RETRY_CNT, data = code[i] + RETRY_CNT;
             (data != code[i]) && max_write_times;
             max_write_times--) {
            data = code[i];
            hdmi_writel(tee->pwd_regs, HDCP2X_BASE_ADDR_MCU_PRAM + i * 4, data); /* 4 is an addr len */
            data = hdmi_readl(tee->pwd_regs, HDCP2X_BASE_ADDR_MCU_PRAM + i * 4); /* 4 is an addr len */
        }

        if (!max_write_times) {
            hi_log_alert("data: %08x, g_8051_mcu_code[%d]: %08x is not equal!\n", data, i, *(code + i));
            ret = HI_FAILURE;
            break;
        }
    }

    return ret;
}

void hdcp2x_set_mode(struct tee_hdmitx *tee)
{
    if (tee == HI_NULL || tee->pwd_regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return ;
    }

    hdmi_clrset(tee->pwd_regs, REG_HDCP_FUN_SEL, REG_HDCP_FUN_SEL_M,
        reg_hdcp_fun_sel(1));
}

hi_s32 hdcp2x_verify_mcu(struct tee_hdmitx *tee)
{
    hi_s32 ret;
    hi_u32 data;

    if (tee == HI_NULL || tee->pwd_regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    data = hdmi_readl(tee->pwd_regs, HDCP2X_BASE_ADDR_MCU_PRAM);
    if (data != g_8051_mcu_code[0]) {
        ret = hdcp2x_load_mcu_code(tee);
    } else {
        ret = HI_SUCCESS;
    }

    return ret;
}

hi_s32 hdcp2x_get_recvid(struct tee_hdmitx *tee, hi_u8 *data, hi_u32 size)
{
    hi_u32 i;

    if (tee == HI_NULL || tee->pwd_regs == HI_NULL || data == HI_NULL ||
        size != HDCP2X_RECVID_SIZE) {
        hi_log_alert("null ptr of err size\n");
        return HI_FAILURE;
    }

    for (i = 0; i < HDCP2X_RECVID_SIZE; i++) {
        data[i] = hdcp2x_dram_read(tee->pwd_regs, HDCP2X_RECVID_ADDR + i);
    }

    return HI_SUCCESS;
}

hi_s32 hdcp2x_get_ds_info(struct tee_hdmitx *tee, struct hdcp2x_downstream_info *ds_info)
{
    hi_u32 value, i;
    hi_u8 *data = HI_NULL;

    if (tee == HI_NULL || tee->pwd_regs == HI_NULL || ds_info == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    value = hdmi_readl(tee->pwd_regs, REG_HDCP2X_RPT_DEV);
    ds_info->depth = (value & REG_HDCP2X_RPT_DEP_CNT_M) >> 5; /* mask start in bit 5 */
    ds_info->dev_cnt = value & REG_HDCP2X_RPT_DEV_CNT_M;
    ds_info->downstream_is_rpt = !!ds_info->dev_cnt;

    value = hdmi_readl(tee->pwd_regs, REG_HDCP2X_RPT_INFO);
    ds_info->max_devs_exceeded = (value & REG_HDCP2X_RPT_DEV_EXC_M) >> 3; /* mask start in bit 3 */
    ds_info->max_cascade_exceeded = (value & REG_HDCP2X_RPT_CAS_EXC_M) >> 2; /* mask start in bit 2 */
    ds_info->hdcp20_repeater_downstream = (value & REG_HDCP20_RPT_ON_M) >> 1; /* mask start in bit 1 */
    ds_info->hdcp1x_device_downstream = value & REG_HDCP1X_DEV_ON_M;

    data = (hi_u8 *)ds_info->recvid;
    for (i = 0; i < HDCP2X_RECVID_SIZE; i++) {
        data[i] = hdcp2x_dram_read(tee->pwd_regs, HDCP2X_RECVID_ADDR + i);
    }

    data = (hi_u8 *)ds_info->recvid_list;
    for (i = 0; (i < ds_info->dev_cnt * HDCP2X_RECVID_SIZE) &&
        (i < sizeof(ds_info->recvid_list)); i++) {
        data[i] = hdcp2x_dram_read(tee->pwd_regs, HDCP2X_RECVID_LIST_ADDR + i);
    }

    return HI_SUCCESS;
}

hi_void hdcp2x_set_stream_id(struct tee_hdmitx *tee, hi_u8 stream_id)
{
    if (tee == HI_NULL || tee->pwd_regs == HI_NULL) {
        hi_log_alert("nul ptr\n");
        return ;
    }

    if (stream_id > 1) {
        hi_log_alert("error stream_id(%d)!\n", stream_id);
        return ;
    }

    hdmi_write_bits(tee->pwd_regs, REG_HDCP2X_RPT_STRM_ID, REG_HDCP2X_RPT_STRM_ID_M, stream_id);
}

hi_void hdcp2x_enable_irq(struct tee_hdmitx *tee, hi_bool enable)
{
    hi_u8 value;

    if (tee == HI_NULL || tee->pwd_regs == HI_NULL) {
        hi_log_alert("nul ptr\n");
        return ;
    }

    value = enable ? REG_HDCP2X_SEC_MASK_B0_ALL : 0x0; /* 0x0 is disable */
    hdmi_write_bits(tee->pwd_regs, REG_SEC_INTR_MASK, REG_MCU_SEC_INTR_MASK, enable);
    hdmi_writel(tee->pwd_regs, REG_HDCP2X_SEC_MASK_B0, value);
}

hi_void hdcp2x_get_irq_status(struct tee_hdmitx *tee, hi_u32 *status)
{
    if (tee == HI_NULL || tee->pwd_regs == HI_NULL || status == HI_NULL) {
        return ;
    }

    *status = hdmi_readl(tee->pwd_regs, REG_HDCP2X_SEC_INTR_B0);
}

hi_void hdcp2x_clear_irq(struct tee_hdmitx *tee, hi_u32 status)
{
    if (tee == HI_NULL || tee->pwd_regs == HI_NULL) {
        return ;
    }

    hdmi_writel(tee->pwd_regs, REG_HDCP2X_SEC_INTR_B0, status);
}

struct tee_hdcp2x_hal_ops g_hal_2x_ops = {
    .load_mcu_code = hdcp2x_load_mcu_code,
    .set_mode = hdcp2x_set_mode,
    .set_stream_id = hdcp2x_set_stream_id,
    .verify_mcu = hdcp2x_verify_mcu,
    .get_ds_info = hdcp2x_get_ds_info,
    .get_recvid = hdcp2x_get_recvid,
    .get_irq_status = hdcp2x_get_irq_status,
    .enable_irq = hdcp2x_enable_irq,
    .clear_irq = hdcp2x_clear_irq,
};

struct tee_hdcp2x_hal_ops *tee_hal_hdmitx_hdcp2x_get_ops(hi_void)
{
    return &g_hal_2x_ops;
}

