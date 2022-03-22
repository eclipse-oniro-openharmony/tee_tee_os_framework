/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display mctl registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "hisi_dss_mctl.h"

static void dss_mctl_clear(struct hisifb_data_type *hisifd)
{
	// set sleep time between clear config to confirm config take effect
	hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_CLEAR, 0x1, 1, 0);
	SRE_SwMsleep(5);
	hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_CLEAR, 0x1, 1, 0);
	SRE_SwMsleep(5);
	hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_CLEAR, 0x1, 1, 0);
	SRE_SwMsleep(32);
}

static void dss_mctl_mutex_lock(struct hisifb_data_type *hisifd)
{
	hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_MUTEX, 0x1, 1, 0);
}

static void dss_mctl_mutex_unlock(struct hisifb_data_type *hisifd)
{
	hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_MUTEX, 0x0, 1, 0);
}
static void dss_mctl_sec_flush_en(struct hisifb_data_type *hisifd)
{
	hisifd->set_reg(hisifd->mctrl_sys_base + MCTL_PAY_SECU_FLUSH_EN, 0x1, 32, 0);
	HISI_FB_INFO("exit!\n");
}

static void dss_enter_display_mctl_config(struct hisifb_data_type *hisifd)
{
	hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_EN, 0x1, 1, 0);

	if (hisifd->mode_cfg == DSS_MIPI_DSI_CMD_MODE) {
		hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_TOP, 0x1, 2, 0); // single flash
	} else {
		hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_TOP, 0x2, 2, 0); // auto flash
		hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_DBG, 0xB13A04, 32, 0);
	}

	hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_MUTEX_SEC_RCH, 0x1, 32, 0);
}

static void dss_enter_display_mctrl_config(struct hisifb_data_type *hisifd)
{
	hisifd->set_reg(hisifd->mctrl_sys_base + MCTL_DSI0_SECU_CFG, 0x1, 32, 0);
	hisifd->set_reg(hisifd->mctrl_sys_base + MCTL_RCH_SECU_GATE, 0x0000004e, 32, 0);
	hisifd->set_reg(hisifd->mctrl_sys_base + MCTL_CTL_SECU_CFG, 0x1, 1, 4);
	/* sec rch ov0 sel */
	hisifd->set_reg(hisifd->mctrl_sys_base + MCTL_RCH_OV0_SEL1, hisifd->sec_rch_idx, 4, 0);
	hisifd->set_reg(hisifd->mctrl_sys_base + MCTL_SEC_RCH_OV_OEN, 0x100, 13, 0);

}

static void dss_exit_display_mctl_mctrl_config(struct hisifb_data_type *hisifd)
{
	hisifd->set_reg(hisifd->mctrl_sys_base + MCTL_DSI0_SECU_CFG, 0x0, 32, 0);
	hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_MUTEX_SEC_RCH, 0x0, 32, 0);
	hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_DBG, 0xB03A20, 32, 0);
	hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_TOP, 0x0, 2, 0);
	hisifd->set_reg(hisifd->mctrl_sys_base + MCTL_RCH_SECU_GATE, 0x0, 32, 0);

	hisifd->set_reg(hisifd->mctrl_sys_base + MCTL_CTL_SECU_CFG, 0x0, 1, 4);
	hisifd->set_reg(hisifd->mctrl_sys_base + MCTL_MOD_DBG, 0xA8000, 32, 0);
	hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_EN, 0x0, 32, 0);
}

void dss_registe_base_mctl_cb(struct dss_mctl_cb *mctl_cb)
{
	HISI_ERR_CHECK_NO_RETVAL((mctl_cb == NULL), "mctl_cb is NULL\n");

	mctl_cb->mctl_clear = dss_mctl_clear;
	mctl_cb->mctl_mutex_lock = dss_mctl_mutex_lock;
	mctl_cb->mctl_mutex_unlock = dss_mctl_mutex_unlock;
	mctl_cb->mctl_sec_flush_en = dss_mctl_sec_flush_en;
	mctl_cb->enter_display_mctl_config = dss_enter_display_mctl_config;
	mctl_cb->enter_display_mctrl_config = dss_enter_display_mctrl_config;
	mctl_cb->exit_display_mctl_mctrl_config = dss_exit_display_mctl_mctrl_config;

	dss_registe_platform_mctl_cb(mctl_cb);
}
