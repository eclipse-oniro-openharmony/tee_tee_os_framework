/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display dfc registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "hisi_dss_dfc.h"
#include "hisi_dss_module_registe.h"

static void dss_display_rdfc_config(struct hisifb_data_type *hisifd, dss_layer_t *layer)
{
	uint32_t dfc_pix_in_num;
	uint32_t size_hrz;
	uint32_t size_vrt;
	struct hisi_dss_module_cb *module_cb = dss_get_module_cb();

	HISI_FB_DEBUG("enter!\n");
	dfc_pix_in_num = (layer->img.bpp > 2) ? 0x0 : 0x1; /* pixel number */

	size_hrz = DSS_WIDTH(layer->src_rect.w);
	size_vrt = DSS_HEIGHT(layer->src_rect.h);

	hisifd->set_reg(hisifd->rdfc_base + DFC_DISP_SIZE, (size_vrt | (size_hrz << 16)), 32, 0);
	hisifd->set_reg(hisifd->rdfc_base + DFC_PIX_IN_NUM, dfc_pix_in_num, 1, 0);
	/* display format: 0x06-ARGB8888, 0x00-RGB565 */
	hisifd->set_reg(hisifd->rdfc_base + DFC_DISP_FMT, ((layer->img.bpp > 2) ? 0x6 : 0x0), 5, 1);

	hisifd->set_reg(hisifd->rdfc_base + DFC_CTL_CLIP_EN, 0x1, 1, 0);
	hisifd->set_reg(hisifd->rdfc_base + DFC_ICG_MODULE, 0x1, 1, 0);

	HISI_CHECK_AND_CALL_FUNC(module_cb->dfc_cb.display_extra_rdfc_config, hisifd);
	HISI_FB_DEBUG("exit!\n");
}

static void dss_display_extra_rdfc_config(struct hisifb_data_type *hisifd)
{
	hisifd->set_reg(hisifd->rdfc_base + DFC_BITEXT_CTL, 0x3, 32, 0);
}


void dss_registe_base_dfc_cb(struct dss_dfc_cb *dfc_cb)
{
	HISI_ERR_CHECK_NO_RETVAL((dfc_cb == NULL), "dfc_cb is NULL\n");

	dfc_cb->display_rdfc_config = dss_display_rdfc_config;
	dfc_cb->display_extra_rdfc_config = dss_display_extra_rdfc_config;

	dss_registe_platform_dfc_cb(dfc_cb);
}


