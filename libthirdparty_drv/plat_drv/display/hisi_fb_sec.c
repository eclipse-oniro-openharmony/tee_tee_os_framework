/* Copyright (c) 2014-2015, Hisilicon Tech. Co., Ltd. All rights reserved.
 *
 */
#include "hisi_disp.h"
#include "hisi_fb_sec.h"
#include "boot_sharedmem.h"
#include "tee_mutex.h"
static void __set_reg(uint32_t addr, uint32_t val, unsigned char bw, unsigned char bs)
{
	uint32_t mask = (1UL << bw) - 1UL;
	uint32_t temp;

	temp = inp32(addr);
	temp &= ~(mask << bs);

	outp32(addr, temp | ((val & mask) << bs));
}

static int __fb_cfg_sec(struct hisifb_data_type *hisifd, int sec_value)
{
	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL!!!");
		return -1;
	}

	if (sec_value == hisifd->secure_status) {
		HISI_FB_ERR("secure status is already %d!!! return...\n", hisifd->secure_status);
		return 0;
	}

	return hisi_dss_sec_pay_config(hisifd, sec_value);
}

static int __wait_vactive_flag(struct hisifb_data_type *hisifd)
{
	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL!!!");
		return -1;
	}
	return hisi_vactive0_start_config(hisifd);
}

static int __wait_release_flag(struct hisifb_data_type *hisifd)
{
	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL!!!");
		return -1;
	}
	return hisi_frame_end_config(hisifd);
}

static int __get_disp_info (struct hisifb_data_type *hisifd, struct hisi_panel_info *pinfo)
{
	hisi_disp_info_t disp_info = { 0 };
	int ret;

	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL!!!");
		return -1;
	}

	if (!pinfo) {
		HISI_FB_ERR("hisifd is NULL!!!");
		return -1;
	}

	if (!hisifd->xres || !hisifd->yres) {
		ret = get_shared_mem_info(TEEOS_SHARED_MEM_DSS, (unsigned int*)&disp_info, sizeof(hisi_disp_info_t));
		if (ret) {
			HISI_FB_ERR("ERROR!!!:failed to get shared mem info\n");
			return -1;
		}
		hisifd->xres = disp_info.xres;
		hisifd->yres = disp_info.yres;
	}

	pinfo->xres = hisifd->xres;
	pinfo->yres = hisifd->yres;
	HISI_FB_DEBUG("xres = %d, yres = %d\n", pinfo->xres, pinfo->yres);

	return 0;
}

static int __pan_display_sec (struct hisifb_data_type *hisifd, dss_layer_t *layer)
{
	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL!!!");
		return -1;
	}
	if (!layer) {
		HISI_FB_ERR("pov_req is NULL!!!");
		return -1;
	}

	/*check secure status*/
	if (SEC_PAY_ENABLE != hisifd->secure_status) {
		HISI_FB_ERR("dss is not in secure pay mode!!!\n");
		return -1;
	}

	return do_pan_display_config(hisifd, layer);
}

static int __panel_power_on(struct hisifb_data_type *hisifd)
{
	uint32_t dss_power_stat;

	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL!!!");
		return -1;
	}

#if defined (CONFIG_DSS_TYPE_KIRIN970) \
	|| defined (CONFIG_DSS_TYPE_KIRIN980) \
	|| defined (CONFIG_DSS_TYPE_KIRIN710) \
	|| defined (CONFIG_DSS_TYPE_ORLANDO) \
	|| defined (CONFIG_DSS_TYPE_KIRIN990)
	dss_power_stat = inp32(hisifd->media1_crg_base + PERSTAT0);
#else
	dss_power_stat = inp32(hisifd->peri_crg_base + PERSTAT3);
#endif
	HISI_FB_DEBUG("panel power status is 0x%x.\n", dss_power_stat);
	if ((dss_power_stat & DSS_POWER_ON_STAT) == DSS_POWER_ON_STAT) {
		return 0;
	} else {
		return -1;
	}
}

int device_probe(struct hisifb_data_type *hisifd)
{
	hisi_disp_info_t disp_info = { 0 };
	int ret = 0;

	if (!hisifd) {
		HISI_FB_ERR("hisifb_data is NULL!!\n");
		return -1;
	}

	hisifd->index = PRIMARY_PANEL_IDX;
	hisifd->dss_base       = DSS_BASE;
	hisifd->peri_crg_base  = PERI_CRG_BASE;
	hisifd->sctrl_base     = SCTRL_BASE;
	hisifd->pctrl_base     = PCTRL_BASE;
	hisifd->mmbuf_crg_base = MMBUF_CFG_BASE;
	hisifd->noc_dss_base   = NOC_DSS_BASE;
	hisifd->mipi_dsi0_base = MIPI_DSI0_BASE;
	hisifd->mipi_dsi1_base = MIPI_DSI1_BASE;
	hisifd->pmc_base       = PMCTRL_BASE;
	hisifd->media1_crg_base = MEDIA1_CRG_BASE;

	hisifd->dpe_sec_irq  = HISI_FB_SEC_IRQ;
	hisifd->sec_rch_idx  = HISI_DSS_SEC_RCH_INDEX;
	hisifd->sec_mctl_idx = DSS_MCTL4;

	hisifd->mode_cfg = DSS_MIPI_DSI_VIDEO_MODE;

	/* func register */
	hisifd->fb_cfg_sec        = __fb_cfg_sec;
	hisifd->get_disp_info     = __get_disp_info;
	hisifd->wait_vactive_flag = __wait_vactive_flag;
	hisifd->wait_release_flag = __wait_release_flag;
	hisifd->pan_display_sec   = __pan_display_sec;
	hisifd->set_reg           = __set_reg;
	hisifd->panel_power_on    = __panel_power_on;

	tee_mutex_init("disp_lock", sizeof("disp_lock"), &hisifd->disp_lock);
	if (!hisifd->xres || !hisifd->yres) {
		/* now dss info is get from system interface, no need to map and copy byself */
		ret = get_shared_mem_info(TEEOS_SHARED_MEM_DSS, (unsigned int*)&disp_info, sizeof(hisi_disp_info_t));
		if (ret) {
			HISI_FB_ERR("ERROR!!!:failed to get shared mem info\n");
			return -1;
		}
		hisifd->xres = disp_info.xres;
		hisifd->yres = disp_info.yres;
	}
	//HISI_FB_INFO("v1 xres = %d, yres = %d\n", hisifd->xres, hisifd->yres);

	ret = memset_s(&(hisifd->layer_prev), sizeof(dss_layer_t), 0, sizeof(dss_layer_t));
	if (ret) {
		HISI_FB_ERR("memcpy_s error: ret=[%d]\n", ret);
	}
	ret = memset_s(&(hisifd->layer), sizeof(dss_layer_t), 0, sizeof(dss_layer_t));
	if (ret) {
		HISI_FB_ERR("memcpy_s error: ret=[%d]\n", ret);
	}
	/* for debug */
	hisifd->disp_debug_dump = 0;

	return 0;
}
