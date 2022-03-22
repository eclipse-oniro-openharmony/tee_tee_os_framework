/* Copyright (c) 2014-2015, Hisilicon Tech. Co., Ltd. All rights reserved.
 *
 */
#include <sre_hwi.h> // HWI_PROC_FUNC
#include "hisi_disp.h"
#include "hisi_fb_sec.h"

void single_frame_update(struct hisifb_data_type *hisifd)
{
	uint32_t ldi_base;
	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return;
	}
	HISI_FB_DEBUG("enter! \n");

#if defined (CONFIG_DSS_TYPE_KIRIN990) || defined (CONFIG_DSS_TYPE_BALTIMORE)
	hisifd->set_reg(hisifd->mipi_dsi0_base + MIPI_LDI_FRM_MSK_UP, 0x1, 1, 0);
	//if (is_dual_mipi_panel(hisifd))
		//hisifd->set_reg(hisifd->mipi_dsi1_base + MIPI_LDI_FRM_MSK_UP, 0x1, 1, 0);
	ldi_base = hisifd->mipi_dsi0_base;
	hisifd->set_reg(ldi_base + MIPI_LDI_CTRL, 0x1, 1, 0);
#else
	ldi_base = hisifd->dss_base + DSS_LDI0_OFFSET;

	hisifd->set_reg(ldi_base + LDI_FRM_MSK_UP, 0x1, 1, 0);
	hisifd->set_reg(ldi_base + LDI_CTRL, 0x1, 1, 0);
#endif

	HISI_FB_DEBUG("exit! \n");
}

////////////////////////////////////////////////////////////////////////////////
static void hisi_dss_mctl_mutex_lock(struct hisifb_data_type *hisifd)
{
	uint32_t mctl_base;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return;
	}

	if (hisifd->sec_mctl_idx >= DSS_MCTL_IDX_MAX) {
		HISI_FB_ERR("sec_mctl_idx is invalid! \n", hisifd->sec_mctl_idx);
		return;
	}

	mctl_base = hisifd->dss_base + g_dss_module_ovl_base[hisifd->sec_mctl_idx][MODULE_MCTL_BASE];

	hisifd->set_reg(mctl_base + MCTL_CTL_MUTEX, 0x1, 1, 0);
}

static void hisi_dss_mctl_mutex_unlock(struct hisifb_data_type *hisifd)
{
	uint32_t mctl_base;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return;
	}

	if (hisifd->sec_mctl_idx >= DSS_MCTL_IDX_MAX) {
		HISI_FB_ERR("sec_mctl_idx is invalid! \n", hisifd->sec_mctl_idx);
		return;
	}

	mctl_base = hisifd->dss_base + g_dss_module_ovl_base[hisifd->sec_mctl_idx][MODULE_MCTL_BASE];

	hisifd->set_reg(mctl_base + MCTL_CTL_MUTEX, 0x0, 1, 0);
}
static void hisi_dss_mctl_sec_flush_en(struct hisifb_data_type *hisifd)
{
	uint32_t mctl_sys_base;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return;
	}
	mctl_sys_base = hisifd->dss_base + DSS_MCTRL_SYS_OFFSET;
	hisifd->set_reg(mctl_sys_base + MCTL_PAY_SECU_FLUSH_EN, 0x1, 32, 0);
	HISI_FB_INFO("exit! \n");
}

static int hisi_dss_check_rch_idle(struct hisifb_data_type *hisifd, uint32_t rch_idx)
{
	uint32_t tmp;
	uint32_t offset;
	uint32_t rdma_base;
	uint32_t rch_cmdlist_base;
	uint32_t dss_base;
	uint32_t mctl_base;
	uint32_t mctrl_sys_base;
	HISI_FB_DEBUG("enter ! \n");

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return -1;
	}

	if (rch_idx >= DSS_CHN_MAX_DEFINE) {
		HISI_FB_ERR("rch_idx is invalid! \n", rch_idx);
		return -1;
	}

	if (hisifd->sec_mctl_idx >= DSS_MCTL_IDX_MAX) {
		HISI_FB_ERR("sec_mctl_idx is invalid! \n", hisifd->sec_mctl_idx);
		return -1;
	}

	dss_base = hisifd->dss_base;
	rdma_base= dss_base + g_dss_module_base[rch_idx][MODULE_DMA];
	mctrl_sys_base = dss_base + DSS_MCTRL_SYS_OFFSET;
	hisifd->set_reg(mctrl_sys_base + MCTL_MOD2_DBG, 0x20000, 32, 0);

	offset = 0x40;
	rch_cmdlist_base = DSS_CMDLIST_OFFSET + CMDLIST_CH0_STATUS + rch_idx * offset;
	tmp = inp32(dss_base + rch_cmdlist_base);
	if ((tmp & 0xF) != 0x0) {
		HISI_FB_ERR("cmdlist_ch%d not in idle state,rch_cmdlist_status=0x%x !\n", hisifd->sec_rch_idx, tmp);
	}

	tmp = inp32(mctrl_sys_base + MCTL_MOD0_STATUS + rch_idx * 0x4);
	if ((tmp & 0x10) != 0x10) {
		HISI_FB_ERR("rch%d not in idle state, rch_status=0x%x !\n", hisifd->sec_rch_idx, tmp);
		hisifd->set_reg(rdma_base + CH_SW_END_REQ, 0x1, 32, 0);
		do {
			SRE_SwMsleep(1);
			tmp = inp32(rdma_base + CH_SW_END_REQ);
		} while (tmp);
	}

	hisifd->set_reg(rdma_base + CH_REG_DEFAULT, 0x1, 32, 0);
	hisifd->set_reg(rdma_base + CH_REG_DEFAULT, 0x0, 32, 0);
	// clear config
	mctl_base = dss_base + g_dss_module_ovl_base[hisifd->sec_mctl_idx][MODULE_MCTL_BASE];
	hisifd->set_reg(mctl_base + MCTL_CTL_CLEAR, 0x1, 1, 0);

	HISI_FB_DEBUG("exit ! \n");

	return 0;
}

static void hisi_enter_secu_pay(struct hisifb_data_type *hisifd)
{
	uint32_t dss_base;
	uint32_t mctl_base;
	uint32_t mctl_sys_base;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return;
	}

	if (hisifd->sec_mctl_idx >= DSS_MCTL_IDX_MAX) {
		HISI_FB_ERR("sec_mctl_idx is invalid! \n", hisifd->sec_mctl_idx);
		return;
	}

	hisi_vactive0_start_config(hisifd);
	HISI_FB_INFO("enter !\n");

	dss_base = hisifd->dss_base;
	mctl_base = dss_base + g_dss_module_ovl_base[hisifd->sec_mctl_idx][MODULE_MCTL_BASE];
	mctl_sys_base = dss_base + DSS_MCTRL_SYS_OFFSET;
	/*lint -e835 -esym(835,*)*/
	hisifd->set_reg(mctl_base + MCTL_CTL_EN, 0x1, 1, 0);
	/*lint +e835 -esym(835,*)*/

	if (hisifd->mode_cfg == DSS_MIPI_DSI_CMD_MODE) {
		hisifd->set_reg(mctl_base + MCTL_CTL_TOP, 0x1, 2, 0); // single flash?
		/* for single mode need */
		//hisifd->set_reg(mctl_base + MCTL_CTL_MUTEX_OV, 1, 32, 0);
		//hisifd->set_reg(mctl_base + MCTL_CTL_MUTEX_ITF, 0x1, 2, 0);
	} else {
		hisifd->set_reg(mctl_base + MCTL_CTL_TOP, 0x2, 2, 0); // auto flash

	#if defined (CONFIG_DSS_TYPE_HI366X) \
		|| defined (CONFIG_DSS_TYPE_KIRIN970) \
		|| defined (CONFIG_DSS_TYPE_KIRIN710) \
		|| defined (CONFIG_DSS_TYPE_KIRIN980) \
		|| defined (CONFIG_DSS_TYPE_ORLANDO) \
		|| defined (CONFIG_DSS_TYPE_KIRIN990) \
		|| defined (CONFIG_DSS_TYPE_BALTIMORE)
		hisifd->set_reg(mctl_base + MCTL_CTL_DBG, 0xB13A04, 32, 0);
	#endif
	}

	hisifd->set_reg(mctl_base + MCTL_CTL_MUTEX_SEC_RCH, 0x1, 32, 0);

	hisi_dss_smmu_config(hisifd, hisifd->sec_rch_idx, 1);
	hisi_dss_mif_config(hisifd, hisifd->sec_rch_idx, 1);

#if defined (CONFIG_DSS_TYPE_KIRIN970) || defined (CONFIG_DSS_TYPE_KIRIN980) || \
    defined (CONFIG_DSS_TYPE_KIRIN990) || defined (CONFIG_DSS_TYPE_BALTIMORE)
	hisifd->set_reg(mctl_sys_base + MCTL_DSI0_SECU_CFG, 0x1, 32, 0);
	hisifd->set_reg(mctl_sys_base + MCTL_CTL_RCH2_SECU_GATE, 0x0000004e, 32, 0);
#elif defined (CONFIG_DSS_TYPE_KIRIN710) || defined(CONFIG_DSS_TYPE_ORLANDO)
	hisifd->set_reg(mctl_sys_base + MCTL_DSI0_SECU_CFG, 0x1, 32, 0);
	hisifd->set_reg(mctl_sys_base + MCTL_CTL_RCH4_SECU_GATE, 0x0000004e, 32, 0);
#else
	hisifd->set_reg(mctl_sys_base + MCTL_DSI0_SECU_CFG_EN, 0x1, 32, 0);
	hisifd->set_reg(mctl_sys_base + MCTL_CTL_SECU_GATE0, 0x003e0000, 32, 0);
#endif

	hisifd->set_reg(mctl_sys_base + MCTL_CTL_SECU_CFG, 0x1, 1, 4);

#if defined (CONFIG_DSS_TYPE_KIRIN970) || defined (CONFIG_DSS_TYPE_KIRIN980) || \
    defined (CONFIG_DSS_TYPE_KIRIN990) || defined (CONFIG_DSS_TYPE_BALTIMORE)
	/* sec rch ov0 sel */
	hisifd->set_reg(mctl_sys_base + MCTL_RCH_OV0_SEL1, hisifd->sec_rch_idx, 4, 0);
	hisifd->set_reg(mctl_sys_base + MCTL_RCH2_OV_OEN, 0x100, 13, 0);
#else
	hisifd->set_reg(mctl_sys_base + MCTL_RCH_OV0_SEL, hisifd->sec_rch_idx, 4, 24);
#endif

#if defined (CONFIG_DSS_TYPE_HI365X)
	hisi_vactive0_start_config(hisifd);
#endif

	HISI_FB_INFO("exit !\n");

	return;
}

int hisi_exit_secu_pay(struct hisifb_data_type *hisifd)
{
	uint32_t tmp = 0;
	uint32_t dss_base;
	uint32_t mctl_base;
	uint32_t ovl_base;
	uint32_t rdma_base;
	uint32_t mctrl_sys_base;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return -1;
	}

	if (hisifd->sec_rch_idx >= DSS_CHN_MAX_DEFINE) {
		HISI_FB_ERR("sec_rch_idx is invalid! \n", hisifd->sec_rch_idx);
		return -1;
	}

	if (hisifd->sec_mctl_idx >= DSS_MCTL_IDX_MAX) {
		HISI_FB_ERR("sec_mctl_idx is invalid! \n", hisifd->sec_mctl_idx);
		return -1;
	}

	HISI_FB_DEBUG("enter ! \n");

	dss_base = hisifd->dss_base;
	mctrl_sys_base = dss_base + DSS_MCTRL_SYS_OFFSET;
	rdma_base = dss_base + g_dss_module_base[hisifd->sec_rch_idx][MODULE_DMA];
	ovl_base  = dss_base + g_dss_module_ovl_base[hisifd->sec_mctl_idx][MODULE_OVL_BASE];
	mctl_base = dss_base + g_dss_module_ovl_base[hisifd->sec_mctl_idx][MODULE_MCTL_BASE];

	hisi_dss_smmu_config(hisifd, hisifd->sec_rch_idx, 0);
	hisi_dss_mif_config(hisifd, hisifd->sec_rch_idx, 0);

	hisifd->set_reg(rdma_base + CH_SW_END_REQ, 0x1, 32, 0);
	do {
		SRE_SwMsleep(1);
		tmp = inp32(rdma_base + CH_SW_END_REQ);
	} while (tmp);

#if defined (CONFIG_DSS_TYPE_KIRIN970) \
	|| defined (CONFIG_DSS_TYPE_KIRIN980) \
	|| defined (CONFIG_DSS_TYPE_KIRIN990) \
	|| defined (CONFIG_DSS_TYPE_ORLANDO) \
	|| defined (CONFIG_DSS_TYPE_KIRIN710) \
	|| defined (CONFIG_DSS_TYPE_BALTIMORE)
	hisifd->set_reg(mctrl_sys_base + MCTL_DSI0_SECU_CFG, 0x0, 32, 0);
#else
	hisifd->set_reg(mctrl_sys_base + MCTL_DSI0_SECU_CFG_EN, 0x0, 32, 0);
#endif

	hisifd->set_reg(mctl_base + MCTL_CTL_MUTEX_SEC_RCH, 0x0, 32, 0);
#if defined (CONFIG_DSS_TYPE_HI365X)
	hisi_vactive0_start_config(hisifd);
#endif

#if defined (CONFIG_DSS_TYPE_HI366X) \
	|| defined (CONFIG_DSS_TYPE_KIRIN970) \
	|| defined (CONFIG_DSS_TYPE_KIRIN980) \
	|| defined (CONFIG_DSS_TYPE_KIRIN990) \
	|| defined (CONFIG_DSS_TYPE_ORLANDO) \
	|| defined(CONFIG_DSS_TYPE_KIRIN710) \
	|| defined (CONFIG_DSS_TYPE_BALTIMORE)
	hisifd->set_reg(mctl_base + MCTL_CTL_DBG, 0xB03A20, 32, 0);
#endif

	hisifd->set_reg(mctl_base + MCTL_CTL_TOP, 0x0, 2, 0);

#if defined (CONFIG_DSS_TYPE_KIRIN970) \
	|| defined (CONFIG_DSS_TYPE_KIRIN980) \
	|| defined (CONFIG_DSS_TYPE_KIRIN990) \
	|| defined (CONFIG_DSS_TYPE_BALTIMORE)
	hisifd->set_reg(mctrl_sys_base + MCTL_CTL_RCH2_SECU_GATE, 0x0, 32, 0);
#elif defined (CONFIG_DSS_TYPE_KIRIN710) || defined (CONFIG_DSS_TYPE_ORLANDO)
	hisifd->set_reg(mctrl_sys_base + MCTL_CTL_RCH4_SECU_GATE, 0x0, 32, 0);
#else
	hisifd->set_reg(mctrl_sys_base + MCTL_CTL_SECU_GATE0, 0x0, 32, 0);
#endif

	hisifd->set_reg(mctrl_sys_base + MCTL_CTL_SECU_CFG, 0x0, 1, 4);

#if defined (CONFIG_DSS_TYPE_KIRIN970) \
	|| defined (CONFIG_DSS_TYPE_KIRIN980) \
	|| defined (CONFIG_DSS_TYPE_KIRIN990) \
	|| defined (CONFIG_DSS_TYPE_ORLANDO) \
	|| defined (CONFIG_DSS_TYPE_KIRIN710) \
	|| defined (CONFIG_DSS_TYPE_BALTIMORE)
	hisifd->set_reg(mctrl_sys_base + MCTL_MOD2_DBG, 0xA8000, 32, 0);
#else
	hisifd->set_reg(mctrl_sys_base + MCTL_MOD2_DBG, 0xA0000, 32, 0);
#endif
	hisifd->set_reg(mctl_base + MCTL_CTL_EN, 0x0, 32, 0);

	if (hisifd->disp_debug_dump == 1) {
		HISI_FB_INFO("dump_dss_reg_info shadow regs: \n");
		hisifd->set_reg(rdma_base + CH_RD_SHADOW, 0x1, 1, 0);
	#if defined (CONFIG_DSS_TYPE_KIRIN970) \
		|| defined (CONFIG_DSS_TYPE_KIRIN980) \
		|| defined (CONFIG_DSS_TYPE_KIRIN990) \
		|| defined (CONFIG_DSS_TYPE_BALTIMORE)
		hisifd->set_reg(ovl_base + OV8_RD_SHADOW_SEL, 0x1, 1, 0);
	#else
		hisifd->set_reg(ovl_base + OVL6_RD_SHADOW_SEL, 0x1, 1, 0);
	#endif
		dump_dss_reg_info(hisifd);

		hisifd->set_reg(rdma_base + CH_RD_SHADOW, 0x0, 1, 0);
	#if defined (CONFIG_DSS_TYPE_KIRIN970) \
		|| defined (CONFIG_DSS_TYPE_KIRIN980) \
		|| defined (CONFIG_DSS_TYPE_KIRIN990) \
		|| defined (CONFIG_DSS_TYPE_BALTIMORE)
		hisifd->set_reg(ovl_base + OV8_RD_SHADOW_SEL, 0x0, 1, 0);
	#else
		hisifd->set_reg(ovl_base + OVL6_RD_SHADOW_SEL, 0x0, 1, 0);
	#endif

		HISI_FB_INFO("dump_dss_reg_info work regs: \n");
		dump_dss_reg_info(hisifd);
	}

	HISI_FB_DEBUG("clear secure config success!\n");
	return 0;
}

static int hisi_dss_sec_config_clear(struct hisifb_data_type *hisifd, uint32_t rch_idx)
{
	uint32_t ovl_base;
	uint32_t rdma_base;
	uint32_t dss_base;
	uint32_t mctrl_sys_base;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return -1;
	}

	if (rch_idx >= DSS_CHN_MAX_DEFINE) {
		HISI_FB_ERR("rch_idx is invalid! \n", rch_idx);
		return -1;
	}

	if (hisifd->sec_mctl_idx >= DSS_MCTL_IDX_MAX) {
		HISI_FB_ERR("sec_mctl_idx is invalid! \n", hisifd->sec_mctl_idx);
		return -1;
	}

	dss_base = hisifd->dss_base;
	ovl_base = dss_base + g_dss_module_ovl_base[hisifd->sec_mctl_idx][MODULE_OVL_BASE];
	rdma_base= dss_base + g_dss_module_base[rch_idx][MODULE_DMA];
	mctrl_sys_base = dss_base + DSS_MCTRL_SYS_OFFSET;

	hisi_dss_mctl_mutex_lock(hisifd);

	hisifd->set_reg(rdma_base + CH_REG_DEFAULT, 0x1, 32, 0);
	hisifd->set_reg(rdma_base + CH_REG_DEFAULT, 0x0, 32, 0);

#if defined (CONFIG_DSS_TYPE_KIRIN970) \
	|| defined (CONFIG_DSS_TYPE_KIRIN980) \
	|| defined (CONFIG_DSS_TYPE_KIRIN990) \
	|| defined (CONFIG_DSS_TYPE_BALTIMORE)
	hisifd->set_reg(ovl_base + OVL_LAYER7_POS, 0x0, 32, 0);
	hisifd->set_reg(ovl_base + OVL_LAYER7_SIZE, 0x0, 32, 0);
	hisifd->set_reg(ovl_base + OVL_LAYER7_ALPHA_MODE, 0x0, 32, 0);
	hisifd->set_reg(ovl_base + OVL_LAYER7_ALPHA_A, 0x0, 32, 0);
	hisifd->set_reg(ovl_base + OVL_LAYER7_CFG, 0x0, 1, 0);
#else
	hisifd->set_reg(ovl_base + OVL_LAYER5_POS, 0x0, 32, 0);
	hisifd->set_reg(ovl_base + OVL_LAYER5_SIZE, 0x0, 32, 0);
	hisifd->set_reg(ovl_base + OVL_LAYER5_ALPHA, 0x0, 32, 0);
	hisifd->set_reg(ovl_base + OVL_LAYER5_CFG, 0x0, 1, 0);
#endif

	hisifd->set_reg(rdma_base + CH_CTL, 0x0, 4, 0);
	hisifd->set_reg(rdma_base + CH_SECU_EN, 0x0, 1, 0);
	hisifd->set_reg(dss_base + g_dss_module_base[rch_idx][MODULE_MCTL_CHN_OV_OEN], 0x0, 1, 8);

#if defined (CONFIG_DSS_TYPE_KIRIN970) \
	|| defined (CONFIG_DSS_TYPE_KIRIN980) \
	|| defined (CONFIG_DSS_TYPE_BALTIMORE) \
	|| defined (CONFIG_DSS_TYPE_KIRIN990)
	hisifd->set_reg(mctrl_sys_base + MCTL_RCH_OV0_SEL1, 0xF, 4, 0);
#else
	hisifd->set_reg(mctrl_sys_base + MCTL_RCH_OV0_SEL, 0xF, 4, 24);
#endif

	hisi_dss_mctl_sec_flush_en(hisifd);
	hisi_dss_mctl_mutex_unlock(hisifd);

	HISI_FB_INFO("clear secure layer config ok, wait for frame update!\n");
	single_frame_update(hisifd);

	// make sure secure layer exit.
	hisi_vactive0_start_config(hisifd);

	return 0;
}

int hisi_dss_sec_pay_config(struct hisifb_data_type *hisifd, int sec_value)
{
	uint32_t ret = 0;
	uint32_t dss_base;
	uint32_t ovl_base;
	uint32_t rdma_base;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return -1;
	}

	if (hisifd->sec_rch_idx >= DSS_CHN_MAX_DEFINE) {
		HISI_FB_ERR("sec_rch_idx is invalid! \n", hisifd->sec_rch_idx);
		return -1;
	}

	if (hisifd->sec_mctl_idx >= DSS_MCTL_IDX_MAX) {
		HISI_FB_ERR("sec_mctl_idx is invalid! \n", hisifd->sec_mctl_idx);
		return -1;
	}

	HISI_FB_INFO("sec_value = %d! enter. \n", sec_value);

	dss_base = hisifd->dss_base;
	rdma_base = dss_base + g_dss_module_base[hisifd->sec_rch_idx][MODULE_DMA];
	ovl_base  = dss_base + g_dss_module_ovl_base[hisifd->sec_mctl_idx][MODULE_OVL_BASE];

	if (sec_value) {
		hisi_dss_check_rch_idle(hisifd, hisifd->sec_rch_idx);
		hisifd->first_frame = 1;
		hisifd->alpha_enable = 0;
		/* set initial flag */
		hisifd->secure_status = SEC_PAY_ENABLE;
		hisi_dss_mcu_interrupt_unmask(hisifd);

		/*register dss secure irq*/
		if (SRE_HwiCreate((HWI_HANDLE_T)hisifd->dpe_sec_irq, (HWI_PRIOR_T)0, (HWI_MODE_T)0,
			(HWI_PROC_FUNC)hisi_fb_irq_handle, (HWI_ARG_T)(uintptr_t)hisifd)) {
			HISI_FB_ERR("failed to create fb irq!\n");
			return -1;
		}

		if (SRE_HwiEnable(hisifd->dpe_sec_irq) != SRE_OK) {
			HISI_FB_ERR("failed to SRE_HwiEnable fb irq!\n");
			return -1;
		}
	} else {
		hisi_vactive0_start_config(hisifd);
		hisi_dss_sec_config_clear(hisifd, hisifd->sec_rch_idx);

		if (hisifd->disp_debug_dump == 1) {
			HISI_FB_INFO("dump_dss_reg_info shadow regs: \n");
			hisifd->set_reg(rdma_base + CH_RD_SHADOW, 0x1, 1, 0);
		#if defined (CONFIG_DSS_TYPE_KIRIN970) \
			|| defined (CONFIG_DSS_TYPE_KIRIN980) \
			|| defined (CONFIG_DSS_TYPE_KIRIN990) \
			|| defined (CONFIG_DSS_TYPE_BALTIMORE)
			hisifd->set_reg(ovl_base + OV8_RD_SHADOW_SEL, 0x1, 1, 0);
		#else
			hisifd->set_reg(ovl_base + OVL6_RD_SHADOW_SEL, 0x1, 1, 0);
		#endif

			dump_dss_reg_info(hisifd);

			hisifd->set_reg(rdma_base + CH_RD_SHADOW, 0x0, 1, 0);
		#if defined (CONFIG_DSS_TYPE_KIRIN970) \
			|| defined (CONFIG_DSS_TYPE_KIRIN980) \
			|| defined (CONFIG_DSS_TYPE_KIRIN990) \
			|| defined (CONFIG_DSS_TYPE_BALTIMORE)
			hisifd->set_reg(ovl_base + OV8_RD_SHADOW_SEL, 0x0, 1, 0);
		#else
			hisifd->set_reg(ovl_base + OVL6_RD_SHADOW_SEL, 0x0, 1, 0);
		#endif

			HISI_FB_INFO("dump_dss_reg_info work regs: \n");
			dump_dss_reg_info(hisifd);
		}
		hisi_exit_secu_pay(hisifd);

		/*deinit initial flag*/
		hisifd->secure_status = SEC_PAY_DISABLE;
		hisi_dss_mcu_interrupt_mask(hisifd);

		ret = SRE_HwiDisable(hisifd->dpe_sec_irq);
		if (ret != 0) {
			HISI_FB_ERR("failed to disable fb irq!\n");
			return -1;
		}

		ret = SRE_HwiDelete(hisifd->dpe_sec_irq);
		if (ret != 0) {
			HISI_FB_ERR("failed to delete fb irq, return!\n");
			return -1;
		}
	}

	HISI_FB_INFO("sec_value = %d! exit.\n", sec_value);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
static void hisi_dss_rdma_config(struct hisifb_data_type *hisifd, dss_layer_t *layer)
{
	dss_rect_t *src_rect = NULL;
	uint32_t aligned_pixel;

	uint32_t rdma_oft_x0;
	uint32_t rdma_oft_y0;
	uint32_t rdma_oft_x1;
	uint32_t rdma_oft_y1;
	uint32_t rdma_stride;
	uint32_t rdma_bpp = 0;
	uint32_t stretch_size_vrt;

	uint32_t dss_base;
	uint32_t rdma_base;
	uint32_t mctl_sys_base;

	if (!hisifd || !layer) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return;
	}

	if (hisifd->sec_rch_idx >= DSS_CHN_MAX_DEFINE) {
		HISI_FB_ERR("sec_rch_idx is invalid! \n", hisifd->sec_rch_idx);
		return;
	}

	HISI_FB_DEBUG("enter! \n");

	dss_base = hisifd->dss_base;
	rdma_base = dss_base + g_dss_module_base[hisifd->sec_rch_idx][MODULE_DMA];
	mctl_sys_base = dss_base + DSS_MCTRL_SYS_OFFSET;
	src_rect = &(layer->src_rect);

	if (!src_rect) {
		HISI_FB_ERR("src_rect is NULL! \n");
		return;
	}

	/* sec rch sel ov0 */
	hisifd->set_reg(mctl_sys_base + MCTL_SEC_RCH_OV_OEN, 0x1, 1, 8);

	if (layer->img.bpp == 4) {
		rdma_bpp = 0x5;
	} else {
		rdma_bpp = 0x0;
	}

	aligned_pixel = DMA_ALIGN_BYTES / layer->img.bpp;

	rdma_oft_x0 = src_rect->x / aligned_pixel;
	rdma_oft_y0 = src_rect->y;
	rdma_oft_x1 = (src_rect->w - 1) / aligned_pixel;
	rdma_oft_y1 = src_rect->h - 1;

	stretch_size_vrt = rdma_oft_y1 - rdma_oft_y0;
	rdma_stride = layer->img.width / aligned_pixel;

	hisifd->set_reg(rdma_base + CH_REG_DEFAULT, 0x1, 32, 0);
	hisifd->set_reg(rdma_base + CH_REG_DEFAULT, 0x0, 32, 0);

	hisifd->set_reg(rdma_base + DMA_OFT_X0, rdma_oft_x0, 12, 0);
	hisifd->set_reg(rdma_base + DMA_OFT_Y0, rdma_oft_y0, 16, 0);
	hisifd->set_reg(rdma_base + DMA_OFT_X1, rdma_oft_x1, 12, 0);
	hisifd->set_reg(rdma_base + DMA_OFT_Y1, rdma_oft_y1, 16, 0);
	hisifd->set_reg(rdma_base + DMA_CTRL, rdma_bpp, 5, 3);
	hisifd->set_reg(rdma_base + DMA_STRETCH_SIZE_VRT, stretch_size_vrt, 32, 0);
	hisifd->set_reg(rdma_base + DMA_DATA_ADDR0, (uint32_t)layer->img.phy_addr, 32, 0);
	hisifd->set_reg(rdma_base + DMA_STRIDE0, rdma_stride, 13, 0);

	hisifd->set_reg(rdma_base + CH_CTL, 0x1, 4, 0);
	hisifd->set_reg(rdma_base + CH_SECU_EN, 0x1, 1, 0);
	HISI_FB_DEBUG("exit! \n");
}

static void hisi_dss_rdfc_config(struct hisifb_data_type *hisifd, dss_layer_t *layer)
{
	uint32_t dfc_pix_in_num ;
	uint32_t size_hrz;
	uint32_t size_vrt;
	uint32_t rdfc_base;

	if (!hisifd || !layer) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return;
	}

	if (hisifd->sec_rch_idx >= DSS_CHN_MAX_DEFINE) {
		HISI_FB_ERR("sec_rch_idx is invalid! \n", hisifd->sec_rch_idx);
		return;
	}

	HISI_FB_DEBUG("enter! \n");

	rdfc_base = hisifd->dss_base +
		g_dss_module_base[hisifd->sec_rch_idx][MODULE_DFC];

	dfc_pix_in_num = (layer->img.bpp > 2) ? 0x0 : 0x1;

	size_hrz = DSS_WIDTH(layer->src_rect.w);
	size_vrt = DSS_HEIGHT(layer->src_rect.h);

	hisifd->set_reg(rdfc_base + DFC_DISP_SIZE, (size_vrt | (size_hrz << 16)), 32, 0);
	hisifd->set_reg(rdfc_base + DFC_PIX_IN_NUM, dfc_pix_in_num, 1, 0);
	hisifd->set_reg(rdfc_base + DFC_DISP_FMT, ((layer->img.bpp > 2) ? 0x6 : 0x0), 5, 1);

	hisifd->set_reg(rdfc_base + DFC_CTL_CLIP_EN, 0x1, 1, 0);
	hisifd->set_reg(rdfc_base + DFC_ICG_MODULE, 0x1, 1, 0);
#if defined (CONFIG_DSS_TYPE_KIRIN970) \
	|| defined (CONFIG_DSS_TYPE_KIRIN980) \
	|| defined (CONFIG_DSS_TYPE_KIRIN990) \
	|| defined (CONFIG_DSS_TYPE_BALTIMORE)
	hisifd->set_reg(rdfc_base + DFC_BITEXT_CTL, 0x3, 32, 0);
#endif
	HISI_FB_DEBUG("exit! \n");
}

int do_pan_display_config(struct hisifb_data_type *hisifd, dss_layer_t *layer)
{
	if (!hisifd || !layer) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return -1;
	}
	HISI_FB_INFO("enter! \n");

	if (hisifd->first_frame) {
		hisi_enter_secu_pay(hisifd);

		if (hisifd->disp_debug_dump == 1) {
			HISI_FB_INFO("dump_dss_reg_info work regs: \n");
			dump_dss_reg_info(hisifd);
		}
		hisifd->first_frame = 0;
	}
	hisi_dss_mctl_mutex_lock(hisifd);
	hisi_dss_rdma_config(hisifd, layer);
	hisi_dss_rdfc_config(hisifd, layer);
	hisi_dss_ovl_layer_config(hisifd, layer);

	hisi_dss_mctl_sec_flush_en(hisifd);
	hisi_dss_mctl_mutex_unlock(hisifd);

	single_frame_update(hisifd);

	if (hisifd->disp_debug_dump == 1) {
		HISI_FB_INFO("dump_dss_reg_info work regs: \n");
		dump_dss_reg_info(hisifd);
	}
	HISI_FB_INFO("exit! \n");
	return 0;
}

