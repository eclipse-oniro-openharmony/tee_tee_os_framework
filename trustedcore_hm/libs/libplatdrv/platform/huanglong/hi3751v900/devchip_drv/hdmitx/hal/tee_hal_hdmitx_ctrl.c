/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: source file of tee ctrl hal layer
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-06-30
 */

#include "hi_log.h"
#include "tee_hal_hdmitx_io.h"
#include "tee_hal_hdmitx_ctrl.h"
#include "tee_drv_hdmitx.h"
#include "tee_hal_hdmitx_reg_ctrl.h"

hi_bool ctrl_get_hpd(struct tee_hdmitx *tee)
{
    hi_bool hpd_pol = HI_FALSE;
    hi_bool hpd = HI_FALSE;

    if (tee == HI_NULL || tee->aon_regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FALSE;
    }

    hpd_pol = hdmi_readl(tee->aon_regs, REG_HOTPLUG_ST_CFG) & REG_HPD_POLARITY_CTL_M;
    hpd = hdmi_readl(tee->aon_regs, REG_TX_AON_STATE) & REG_HOTPLUG_STATE_M;

    if (hpd_pol) {
        return !hpd;
    }

    return !!hpd;
}

hi_bool ctrl_get_phy_is_on(struct tee_hdmitx *tee)
{
    hi_u32 val;

    if (tee == HI_NULL || tee->phy_regs == HI_NULL) {
        hi_log_alert("null ptr!\n");
        return HI_FALSE;
    }

    val = hdmi_readl(tee->phy_regs, REG_HDMI_OE_CFG);
    if ((val & REG_CFG_HDMI_OE_CH0_M) &&
        (val & REG_CFG_HDMI_OE_CH1_M) &&
        (val & REG_CFG_HDMI_OE_CH2_M) &&
        (val & REG_CFG_HDMI_OE_CH3_M)) {
        return HI_TRUE;
    }
    return HI_FALSE;
}

hi_bool ctrl_get_rsen(struct tee_hdmitx *tee)
{
    hi_bool rsen = HI_FALSE;

    if (tee == HI_NULL || tee->aon_regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FALSE;
    }

    rsen = hdmi_readl(tee->aon_regs, REG_TX_AON_STATE) & REG_PHY_RX_SENSE_M;

    return !!rsen;
}

hi_bool ctrl_get_mcu_rst(struct tee_hdmitx *tee)
{
    hi_bool rst = HI_FALSE;

    if (tee == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FALSE;
    }

    rst = hdmi_read_bits(tee->pwd_regs, REG_TX_PWD_RST_CTRL, REG_TX_MCU_SRST_REQ_M);

    return !!rst;
}

hi_void ctrl_set_base_addr(struct tee_hdmitx *tee)
{
    if (tee == HI_NULL || tee->ctrl_ops == HI_NULL) {
        hi_log_alert("null ptr\n");
        return ;
    }

    if (tee->dev_id == TEE_HDMITX_ID_0) {
        tee->pwd_regs = (hi_void *)TEE_HDMITX0_BASE_PWD;
        tee->aon_regs = (hi_void *)TEE_HDMITX0_BASE_AON;
        tee->phy_regs = (hi_void *)TEE_HDMITX0_BASE_PHY;
        tee->sec_irq_num = TEE_HDMITX0_SEC_IRQ_NUM;
    } else if (tee->dev_id == TEE_HDMITX_ID_1) {
        tee->pwd_regs = (hi_void *)TEE_HDMITX1_BASE_PWD;
        tee->aon_regs = (hi_void *)TEE_HDMITX1_BASE_AON;
        tee->phy_regs = (hi_void *)TEE_HDMITX1_BASE_PHY;
        tee->sec_irq_num = TEE_HDMITX1_SEC_IRQ_NUM;
    } else {
        hi_log_alert("id=%d,too large,error!\n", tee->dev_id);
    }
}

struct tee_ctrl_hal_ops g_hal_ctrl_ops = {
    .set_base_addr = ctrl_set_base_addr,
    .get_hpd = ctrl_get_hpd,
    .get_rsen = ctrl_get_rsen,
    .get_phy_is_on = ctrl_get_phy_is_on,
    .get_mcu_rst = ctrl_get_mcu_rst,
};

struct tee_ctrl_hal_ops *tee_hal_hdmitx_ctrl_get_ops(hi_void)
{
    return &g_hal_ctrl_ops;
}

