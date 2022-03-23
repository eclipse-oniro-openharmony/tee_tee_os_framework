/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee hdmitx hal reg layer ctrl head file
 * Author: Hisilicon HDMI software group
 *  Create: 2019-01-17
 */

#ifndef __TEE_HAL_HDMITX_CTRL_REG_H__
#define __TEE_HAL_HDMITX_CTRL_REG_H__

#define TEE_HDMITX_SOFT_INTERUPT_BASE  32
#define TEE_HDMITX0_SEC_IRQ_NUM       (145 + TEE_HDMITX_SOFT_INTERUPT_BASE)
#define TEE_HDMITX1_SEC_IRQ_NUM       (142 + TEE_HDMITX_SOFT_INTERUPT_BASE)

#define TEE_HDMITX0_BASE_PWD          0x01040000
#define TEE_HDMITX0_BASE_AON          0x008d0000
#define TEE_HDMITX0_BASE_PHY          0x0103f000
#define TEE_HDMITX1_BASE_PWD          0x01000000
#define TEE_HDMITX1_BASE_AON          0x010f8000
#define TEE_HDMITX1_BASE_PHY          0x0107f000

#define REG_TX_PWD_RST_CTRL           0x0010
#define reg_clk_test_out_sel(x)       (((x) & 1) << 23) /* [23] */
#define REG_CLK_TEST_OUT_SEL_M        (1 << 23)
#define reg_clk_frl_source_sel(x)     (((x) & 1) << 22) /* [22] */
#define REG_CLK_FRL_SOURCE_SEL_M      (1 << 22)
#define reg_clk_tmds_source_sel(x)    (((x) & 1) << 21) /* [21] */
#define REG_CLK_TMDS_SOURCE_SEL_M     (1 << 21)
#define reg_audpath_acr_clk_sel(x)    (((x) & 1) << 20) /* [20] */
#define REG_AUDPATH_ACR_CLK_SEL_M     (1 << 20)
#define reg_dsc_clk_sel(x)            (((x) & 1) << 19) /* [19] */
#define REG_DSC_CLK_SEL_M             (1 << 19)
#define reg_aud_clk_gen_sel(x)        (((x) & 1) << 18) /* [18] */
#define REG_AUD_CLK_GEN_SEL_M         (1 << 18)
#define reg_vidpath_clk_sel(x)        (((x) & 1) << 17) /* [17] */
#define REG_VIDPATH_CLK_SEL_M         (1 << 17)
#define reg_vidpath_dout_clk_sel(x)   (((x) & 1) << 16) /* [16] */
#define REG_VIDPATH_DOUT_CLK_SEL_M    (1 << 16)
#define reg_tx_csc_dither_srst_req(x) (((x) & 1) << 13) /* [13] */
#define REG_TX_CSC_DITHER_SRST_REQ_M  (1 << 13)
#define reg_frl_fast_arst_req(x)      (((x) & 1) << 12) /* [12] */
#define REG_FRL_FAST_ARST_REQ_M       (1 << 12)
#define reg_frl_soft_arst_req(x)      (((x) & 1) << 11) /* [11] */
#define REG_FRL_SOFT_ARST_REQ_M       (1 << 11)
#define reg_tx_mcu_srst_req(x)        (((x) & 1) << 10) /* [10] */
#define REG_TX_MCU_SRST_REQ_M         (1 << 10)
#define reg_tx_hdcp2x_srst_req(x)     (((x) & 1) << 9) /* [9] */
#define REG_TX_HDCP2X_SRST_REQ_M      (1 << 9)
#define reg_tx_afifo_srst_req(x)      (((x) & 1) << 8) /* [8] */
#define REG_TX_AFIFO_SRST_REQ_M       (1 << 8)
#define reg_tx_acr_srst_req(x)        (((x) & 1) << 7) /* [7] */
#define REG_TX_ACR_SRST_REQ_M         (1 << 7)
#define reg_tx_aud_srst_req(x)        (((x) & 1) << 6) /* [6] */
#define REG_TX_AUD_SRST_REQ_M         (1 << 6)
#define reg_tx_phy_srst_req(x)        (((x) & 1) << 5) /* [5] */
#define REG_TX_PHY_SRST_REQ_M         (1 << 5)
#define reg_tx_hdcp1x_srst_req(x)     (((x) & 1) << 4) /* [4] */
#define REG_TX_HDCP1X_SRST_REQ_M      (1 << 4)
#define reg_tx_hdmi_srst_req(x)       (((x) & 1) << 3) /* [3] */
#define REG_TX_HDMI_SRST_REQ_M        (1 << 3)
#define reg_tx_vid_srst_req(x)        (((x) & 1) << 2) /* [2] */
#define REG_TX_VID_SRST_REQ_M         (1 << 2)
#define reg_tx_sys_srst_req(x)        (((x) & 1) << 1) /* [1] */
#define REG_TX_SYS_SRST_REQ_M         (1 << 1)
#define reg_tx_pwd_srst_req(x)        (((x) & 1) << 0) /* [0] */
#define REG_TX_PWD_SRST_REQ_M         (1 << 0)

#define REG_HOTPLUG_ST_CFG           0x0020
#define reg_osc_div_cnt(x)           (((x) & 0xfff) << 4) /* [15:4] */
#define REG_OSC_DIV_CNT_M            (0xfff << 4)
#define reg_hpd_soft_value(x)        (((x) & 1) << 3) /* [3] */
#define REG_HPD_SOFT_VALUE_M         (1 << 3)
#define reg_hpd_polarity_ctl(x)      (((x) & 1) << 1) /* [2] */
#define REG_HPD_POLARITY_CTL_M       (1 << 1)
#define reg_hpd_override_en(x)       (((x) & 1) << 1) /* [1] */
#define REG_HPD_OVERRIDE_EN_M        (1 << 1)
#define reg_hpd_fillter_en(x)        (((x) & 1) << 0) /* [0] */
#define REG_HPD_FILLTER_EN_M         (1 << 0)

#define REG_TX_AON_STATE             0x0028
#define reg_phy_rx_sense(x)          (((x) & 1) << 1) /* [1] */
#define REG_PHY_RX_SENSE_M           (1 << 1)
#define reg_hotplug_state(x)         (((x) & 1) << 0) /* [0] */
#define REG_HOTPLUG_STATE_M          (1 << 0)

#define REG_HDMI_OE_CFG              0x520
#define REG_CFG_OE_SYNC_EN_M         (1 << 4)
#define REG_CFG_HDMI_OE_CH3_M        (1 << 3)
#define REG_CFG_HDMI_OE_CH2_M        (1 << 2)
#define REG_CFG_HDMI_OE_CH1_M        (1 << 1)
#define REG_CFG_HDMI_OE_CH0_M        (1 << 0)

#endif /* __TEE_HAL_HDMITX_CTRL_REG_H__ */
