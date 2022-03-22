/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: source file of tee hdcp1.x hal layer
 * Author: Hisilicon multimedia interface software group
 * Create: 2019-01-17
 */

#include "hi_log.h"
#include "tee_hal_hdmitx_io.h"
#include "tee_hal_hdmitx_hdcp1x.h"
#include "tee_drv_hdmitx.h"
#include "tee_hal_hdmitx_reg_hdcp.h"

#define REG_HDCP1X_BYTE3_M (0xff << 24)
#define REG_HDCP1X_BYTE2_M (0xff << 16)
#define REG_HDCP1X_BYTE1_M (0xff << 8)
#define REG_HDCP1X_BYTE0_M (0xff << 0)

static hi_void hal_hdcp1x_set_fun_mode(struct tee_hdmitx *tee)
{
    if (tee == HI_NULL || tee->pwd_regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return ;
    }

    hdmi_write_bits(tee->pwd_regs, REG_HDCP_FUN_SEL, REG_HDCP_FUN_SEL_M, 0); /* 0-hdcp1.x, 1-hdcp2.x */
}

static hi_s32 hal_hdcp1x_get_fun_mode(struct tee_hdmitx *tee)
{
    if (tee == HI_NULL || tee->pwd_regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return 0;
    }

    return hdmi_read_bits(tee->pwd_regs, REG_HDCP_FUN_SEL, REG_HDCP_FUN_SEL_M); /* 0-hdcp1.x, 1-hdcp2.x */
}

static hi_s32 hal_hdcp1x_verify_r0(struct tee_hdmitx *tee, hi_u8 *b_r0, hi_u32 size)
{
    hi_u8 a_r0[HDCP1X_RI_SIZE_2BYTES];

    if ((tee == HI_NULL) || tee->pwd_regs == HI_NULL || (b_r0 == HI_NULL)) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }
    if (size != HDCP1X_RI_SIZE_2BYTES) {
        hi_log_alert("ri size err\n");
        return HI_FAILURE;
    }

    /* Ri */
    if (!hdmi_read_bits(tee->pwd_regs, REG_HDCP1X_ENG_STATUS, REG_HDCP1X_RI_RDY_M)) {
        hi_log_alert("hdcp14 hdcp1x_ri_rdy=0\n");
    }

    a_r0[0] = hdmi_read_bits(tee->pwd_regs, REG_HDCP1X_ENG_RI, REG_HDCP1X_ENG_RI0_M);
    a_r0[1] = hdmi_read_bits(tee->pwd_regs, REG_HDCP1X_ENG_RI, REG_HDCP1X_ENG_RI1_M);

    if (a_r0[0] != b_r0[0] || a_r0[1] != b_r0[1]) {
        hi_log_alert("r0 != r0' \n");
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_void hal_hdcp1x_set_b_ksv(struct tee_hdmitx *tee, hi_u8 *bksv, hi_u32 size)
{
    if ((tee == HI_NULL) || tee->pwd_regs == HI_NULL || (bksv == HI_NULL)) {
        hi_log_alert("null ptr\n");
        return ;
    }

    if (size != HDCP1X_KSV_SIZE_5BYTES) {
        hi_log_alert("ksv size err\n");
        return ;
    }

    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_ENG_BKSV0, REG_HDCP1X_KEY_BKSV_BYTE0_M, *bksv++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_ENG_BKSV0, REG_HDCP1X_KEY_BKSV_BYTE1_M, *bksv++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_ENG_BKSV0, REG_HDCP1X_KEY_BKSV_BYTE2_M, *bksv++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_ENG_BKSV0, REG_HDCP1X_KEY_BKSV_BYTE3_M, *bksv++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_ENG_BKSV1, REG_HDCP1X_KEY_BKSV_BYTE4_M, *bksv++);

    if (hdmi_read_bits(tee->pwd_regs, REG_HDCP1X_ENG_STATUS, REG_HDCP1X_RI_RDY_M)) {
        hi_log_alert("set bksv fail!\n");
    }

    return ;
}

static hi_void hal_hdcp1x_set_b_ksv_list(struct tee_hdmitx *tee,
    hi_u8 *bksv_list, hi_u32 buf_size, hi_u32 avail_size)
{
    hi_u32 i;

    if ((tee == HI_NULL) || tee->pwd_regs == HI_NULL || (bksv_list == HI_NULL)) {
        hi_log_alert("null ptr\n");
        return;
    }
    for (i = 0; i < avail_size && i < buf_size; i++) {
        hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_KLIST, REG_HDCP1X_RPT_KLIST_M, bksv_list[i]);
    }
}

static hi_void hal_hdcp1x_set_encryption(struct tee_hdmitx *tee, hi_bool enable)
{
    if (tee == HI_NULL || tee->pwd_regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return;
    }

    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_SEC_CFG, REG_HDCP1X_SEC_ENC_EN_M, enable);
}

static hi_bool hal_hdcp1x_get_encryption(struct tee_hdmitx *tee)
{
    hi_bool encrypiton = HI_FALSE;

    if (tee == HI_NULL || tee->pwd_regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FALSE;
    }

    encrypiton = hdmi_read_bits(tee->pwd_regs, REG_HDCP1X_SEC_CFG, REG_HDCP1X_SEC_ENC_EN_M);

    return !!encrypiton;
}

static hi_void hal_hdcp1x_set_repeater(struct tee_hdmitx *tee, hi_bool enable)
{
    if (tee == HI_NULL || tee->pwd_regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return;
    }
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_SEC_CFG, REG_HDCP1X_SEC_RPT_ON_M, enable);
}

static hi_void hal_hdcp1x_set_b_vi(struct tee_hdmitx *tee, hi_u8 *v_bi, hi_u32 size)
{
    if ((tee == HI_NULL) || tee->pwd_regs == HI_NULL || (v_bi == HI_NULL)) {
        hi_log_alert("null ptr\n");
        return;
    }
    if (size != HDCP1X_VI_SIZE_20BYTES) {
        hi_log_alert("vi size err\n");
        return;
    }

    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V0, REG_HDCP1X_BYTE0_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V0, REG_HDCP1X_BYTE1_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V0, REG_HDCP1X_BYTE2_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V0, REG_HDCP1X_BYTE3_M, *v_bi++);

    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V1, REG_HDCP1X_BYTE0_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V1, REG_HDCP1X_BYTE1_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V1, REG_HDCP1X_BYTE2_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V1, REG_HDCP1X_BYTE3_M, *v_bi++);

    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V2, REG_HDCP1X_BYTE0_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V2, REG_HDCP1X_BYTE1_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V2, REG_HDCP1X_BYTE2_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V2, REG_HDCP1X_BYTE3_M, *v_bi++);

    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V3, REG_HDCP1X_BYTE0_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V3, REG_HDCP1X_BYTE1_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V3, REG_HDCP1X_BYTE2_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V3, REG_HDCP1X_BYTE3_M, *v_bi++);

    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V4, REG_HDCP1X_BYTE0_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V4, REG_HDCP1X_BYTE1_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V4, REG_HDCP1X_BYTE2_M, *v_bi++);
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_RPT_V4, REG_HDCP1X_BYTE3_M, *v_bi++);

    /* enable logic to cmp Vi & Vi' */
    hdmi_write_bits(tee->pwd_regs, REG_HDCP1X_SHA_CHECK, REG_HDCP1X_SHA_CHECK_M, HI_TRUE);
}

static hi_u16 hal_hdcp1x_get_b_status(struct tee_hdmitx *tee)
{
    hi_u16 status;

    if ((tee == HI_NULL) || (tee->pwd_regs == HI_NULL)) {
        hi_log_alert("null ptr\n");
        return 0;
    }

    status = hdmi_read_bits(tee->pwd_regs, REG_HDCP1X_RPT_BSTATUS, REG_HDCP1X_BSTATUS_M);

    return status;
}

static struct tee_hdcp1x_hal_ops g_hal_hdcp1x_ops = {
    .set_mode = hal_hdcp1x_set_fun_mode,
    .get_mode =  hal_hdcp1x_get_fun_mode,
    .verify_r0 = hal_hdcp1x_verify_r0,
    .set_b_ksv = hal_hdcp1x_set_b_ksv,
    .set_b_ksv_list = hal_hdcp1x_set_b_ksv_list,
    .set_encryption = hal_hdcp1x_set_encryption,
    .get_encryption = hal_hdcp1x_get_encryption,
    .set_repeater = hal_hdcp1x_set_repeater,
    .set_b_vi = hal_hdcp1x_set_b_vi,
    .get_b_status = hal_hdcp1x_get_b_status,
};

struct tee_hdcp1x_hal_ops *tee_hal_hdmitx_hdcp1x_get_ops(hi_void)
{
    return &g_hal_hdcp1x_ops;
}

