/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display hisifd data struct initialize
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */
#include <register_ops.h> // writel
#include "tee_mutex.h"
#include "hisi_fb_sec.h"
#include "hisi_overlay_utils.h"
#include "boot_sharedmem.h"
#include "hisi_dss_module_registe.h"
#include "iomgr_ext.h"

static void set_reg(uint32_t addr, uint32_t val, unsigned char bw, unsigned char bs)
{
	uint32_t mask = (1UL << bw) - 1UL;
	uint32_t temp;

	temp = inp32(addr);
	temp &= ~(mask << bs);

	outp32(addr, temp | ((val & mask) << bs));
}

static int fb_cfg_sec(struct hisifb_data_type *hisifd, int sec_value)
{
	HISI_ERR_CHECK_RETURN((hisifd == NULL), -1, "hisifd is NULL\n");

	if (sec_value == hisifd->secure_status) {
		HISI_FB_ERR("secure status is already %d!!! return\n", hisifd->secure_status);
		return 0;
	}

	return hisi_secure_display_config(hisifd, sec_value);
}

static int wait_vactive_flag(struct hisifb_data_type *hisifd)
{
	return hisi_vactive0_start_config(hisifd);
}

static int wait_release_flag(struct hisifb_data_type *hisifd)
{
	return hisi_frame_end_config(hisifd);
}

static int get_disp_xyres(uint32_t *xres, uint32_t *yres)
{
	struct hisi_disp_info disp_info = { 0 };
	int ret;

	if ((*xres != 0) && (*yres != 0))
		return 0;

	ret = get_shared_mem_info(TEEOS_SHARED_MEM_DSS, (unsigned int *)&disp_info, sizeof(struct hisi_disp_info));
	if (ret) {
		HISI_FB_ERR("ERROR!!!:failed to get shared mem info\n");
		return -1;
	}
	*xres = disp_info.xres;
	*yres = disp_info.yres;
	return 0;
}

static int get_disp_info(struct hisifb_data_type *hisifd, struct hisi_panel_info *pinfo)
{
	HISI_ERR_CHECK_RETURN((hisifd == NULL || pinfo == NULL), -1, "input parameter is NULL\n");

	if (get_disp_xyres(&(hisifd->xres), &(hisifd->yres)) != 0)
		return -1;

	hisifd->xres = pinfo->xres;
	hisifd->yres = pinfo->yres;
	HISI_FB_DEBUG("xres = %u, yres = %u\n", pinfo->xres, pinfo->yres);
	return 0;
}

static int pan_display_sec(struct hisifb_data_type *hisifd, dss_layer_t *layer)
{
	HISI_ERR_CHECK_RETURN((hisifd == NULL || layer == NULL), -1, "input parameter is NULL\n");

	/* check secure status */
	if (hisifd->secure_status != SEC_PAY_ENABLE) {
		HISI_FB_ERR("dss is not in secure pay mode!!!\n");
		return -1;
	}

	return do_pan_display_config(hisifd, layer);
}

static int panel_power_on(struct hisifb_data_type *hisifd)
{
	uint32_t dss_power_stat;

	HISI_ERR_CHECK_RETURN((hisifd == NULL), -1, "hisifd is NULL\n");

	dss_power_stat = inp32(hisifd->media1_crg_base + PERSTAT0);
	HISI_FB_DEBUG("panel power status is 0x%x\n", dss_power_stat);

	if ((dss_power_stat & DSS_POWER_ON_STAT) == DSS_POWER_ON_STAT)
		return 0;

	HISI_FB_INFO("hisi fb is already power off!\n");
	return -1;
}

static int hisifd_parameter_init(struct hisifb_data_type *hisifd)
{
	errno_t err;

	hisifd->index = PRIMARY_PANEL_IDX;
	hisifd->dpe_sec_irq  = HISI_FB_SEC_IRQ;
	hisifd->mode_cfg = DSS_MIPI_DSI_VIDEO_MODE;

	tee_mutex_init("disp_lock", sizeof("disp_lock"), &hisifd->disp_lock);
	if (get_disp_xyres(&(hisifd->xres), &(hisifd->yres)) != 0)
		return -1;

	err = memset_s(&(hisifd->layer_prev), sizeof(dss_layer_t), 0, sizeof(dss_layer_t));
	if (err != EOK)
		HISI_FB_ERR("memcpy_s error: ret=[%d]\n", err);

	err = memset_s(&(hisifd->layer), sizeof(dss_layer_t), 0, sizeof(dss_layer_t));
	if (err != EOK)
		HISI_FB_ERR("memcpy_s error: ret=[%d]\n", err);

	/* for debug */
	hisifd->disp_debug_dump = 0;
	return 0;
}

static int hisifd_base_address_init(struct hisifb_data_type *hisifd)
{
	hisifd->dss_base       = DSS_BASE;
	hisifd->peri_crg_base  = PERI_CRG_BASE;
	hisifd->sctrl_base     = SCTRL_BASE;
	hisifd->pctrl_base     = PCTRL_BASE;
	hisifd->mmbuf_crg_base = MMBUF_CFG_BASE;
	hisifd->noc_dss_base   = NOC_DSS_BASE;
	hisifd->mipi_dsi0_base = MIPI_DSI0_BASE;
	hisifd->mipi_dsi1_base = MIPI_DSI1_BASE;
	hisifd->pmc_base       = PMCTRL_BASE;
	hisifd->media1_crg_base = MEDIA_CRG_BASE;

	hisifd->sec_rch_idx  = HISI_DSS_SEC_RCH_INDEX;
	hisifd->sec_mctl_idx = DSS_MCTL4;

	HISI_ERR_CHECK_RETURN((hisifd->sec_mctl_idx >= DSS_MCTL_IDX_MAX), -1, "mctl_idx is invalid!\n");
	HISI_ERR_CHECK_RETURN((hisifd->sec_rch_idx >= DSS_CHN_MAX_DEFINE), -1, "sec_rch_idx is invalid\n");

	hisifd->mctrl_sys_base = hisifd->dss_base + DSS_MCTRL_SYS_OFFSET;
	hisifd->rdma_base = hisifd->dss_base + g_dss_module_base[hisifd->sec_rch_idx][MODULE_DMA];
	hisifd->ovl_base  = hisifd->dss_base + g_dss_module_ovl_base[hisifd->sec_mctl_idx][MODULE_OVL_BASE];
	hisifd->mctl_base = hisifd->dss_base + g_dss_module_ovl_base[hisifd->sec_mctl_idx][MODULE_MCTL_BASE];
	hisifd->rdfc_base = hisifd->dss_base + g_dss_module_base[hisifd->sec_rch_idx][MODULE_DFC];
	hisifd->mif_ch_base = hisifd->dss_base + g_dss_module_base[hisifd->sec_rch_idx][MODULE_MIF_CHN];
	hisifd->smmu_base = hisifd->dss_base + DSS_SMMU_OFFSET;
	return 0;
}

static void hisifd_function_init(struct hisifb_data_type *hisifd)
{
	hisifd->fb_cfg_sec        = fb_cfg_sec;
	hisifd->get_disp_info     = get_disp_info;
	hisifd->wait_vactive_flag = wait_vactive_flag;
	hisifd->wait_release_flag = wait_release_flag;
	hisifd->pan_display_sec   = pan_display_sec;
	hisifd->set_reg           = set_reg;
	hisifd->panel_power_on    = panel_power_on;

	dss_registe_module_cb();
}

int device_probe(struct hisifb_data_type *hisifd)
{
	int ret;

	HISI_ERR_CHECK_RETURN((hisifd == NULL), -1, "hisifd is NULL\n");

	ret = hisifd_base_address_init(hisifd);
	if (ret)
		return ret;

	ret = hisifd_parameter_init(hisifd);
	if (ret)
		return ret;

	hisifd_function_init(hisifd);
	return 0;
}
