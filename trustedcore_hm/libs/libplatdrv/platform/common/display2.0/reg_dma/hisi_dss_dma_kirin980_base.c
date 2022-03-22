/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display dma registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "hisi_dss_dma.h"

static void dss_exit_display_rdma_config(struct hisifb_data_type *hisifd)
{
	uint32_t tmp = 0;

	hisifd->set_reg(hisifd->rdma_base + CH_SW_END_REQ, 0x1, 32, 0);
	do {
		SRE_SwMsleep(1);
		tmp = inp32(hisifd->rdma_base + CH_SW_END_REQ);
	} while (tmp);
}

static void dss_display_rdma_config(struct hisifb_data_type *hisifd, dss_layer_t *layer)
{
	dss_rect_t *src_rect = NULL;
	uint32_t aligned_pixel;

	uint32_t rdma_oft_x0;
	uint32_t rdma_oft_y0;
	uint32_t rdma_oft_x1;
	uint32_t rdma_oft_y1;
	uint32_t rdma_stride;
	uint32_t rdma_bpp;
	uint32_t stretch_size_vrt;

	HISI_FB_DEBUG("enter!\n");
	src_rect = &(layer->src_rect);

	/* sec rch sel ov0 */
	hisifd->set_reg(hisifd->mctrl_sys_base + MCTL_SEC_RCH_OV_OEN, 0x1, 1, 8);
	rdma_bpp = (layer->img.bpp == 4) ? 0x5 : 0x0; /* 0x05-ARGB8888, 0x00-RGB565 */

	HISI_ERR_CHECK_NO_RETVAL((layer->img.bpp == 0), "layer->img.bpp is 0, do division fail\n");
	aligned_pixel = DMA_ALIGN_BYTES / layer->img.bpp;
	HISI_ERR_CHECK_NO_RETVAL((aligned_pixel == 0), "aligned_pixel is 0, do division fail\n");

	rdma_oft_x0 = src_rect->x / aligned_pixel;
	rdma_oft_y0 = src_rect->y;
	rdma_oft_x1 = (src_rect->w - 1) / aligned_pixel;
	rdma_oft_y1 = src_rect->h - 1;

	stretch_size_vrt = rdma_oft_y1 - rdma_oft_y0;
	rdma_stride = layer->img.width / aligned_pixel;

	hisifd->set_reg(hisifd->rdma_base + CH_REG_DEFAULT, 0x1, 32, 0);
	hisifd->set_reg(hisifd->rdma_base + CH_REG_DEFAULT, 0x0, 32, 0);

	hisifd->set_reg(hisifd->rdma_base + DMA_OFT_X0, rdma_oft_x0, 12, 0);
	hisifd->set_reg(hisifd->rdma_base + DMA_OFT_Y0, rdma_oft_y0, 16, 0);
	hisifd->set_reg(hisifd->rdma_base + DMA_OFT_X1, rdma_oft_x1, 12, 0);
	hisifd->set_reg(hisifd->rdma_base + DMA_OFT_Y1, rdma_oft_y1, 16, 0);
	hisifd->set_reg(hisifd->rdma_base + DMA_CTRL, rdma_bpp, 5, 3);
	hisifd->set_reg(hisifd->rdma_base + DMA_STRETCH_SIZE_VRT, stretch_size_vrt, 32, 0);
	hisifd->set_reg(hisifd->rdma_base + DMA_DATA_ADDR0, (uint32_t)layer->img.phy_addr, 32, 0);
	hisifd->set_reg(hisifd->rdma_base + DMA_STRIDE0, rdma_stride, 13, 0);

	hisifd->set_reg(hisifd->rdma_base + CH_CTL, 0x1, 4, 0);
	hisifd->set_reg(hisifd->rdma_base + CH_SECU_EN, 0x1, 1, 0);
	HISI_FB_DEBUG("exit!\n");
}

static void dss_check_rch_idle(struct hisifb_data_type *hisifd)
{
	uint32_t tmp;
	uint32_t offset;
	uint32_t rch_cmdlist_base;

	HISI_ERR_CHECK_NO_RETVAL((hisifd->sec_rch_idx >= DSS_CHN_MAX_DEFINE), "sec_rch_idx is invalid\n");

	HISI_FB_DEBUG("enter !\n");
	hisifd->set_reg(hisifd->mctrl_sys_base + MCTL_MOD_DBG, 0x20000, 32, 0);

	offset = 0x40; // register step
	rch_cmdlist_base = DSS_CMDLIST_OFFSET + CMDLIST_CH0_STATUS + hisifd->sec_rch_idx * offset;
	tmp = inp32(hisifd->dss_base + rch_cmdlist_base);
	if ((tmp & 0xF) != 0x0)
		HISI_FB_ERR("cmdlist_ch%d not in idle state,rch_cmdlist_status=0x%x !\n", hisifd->sec_rch_idx, tmp);

	tmp = inp32(hisifd->mctrl_sys_base + MCTL_MOD0_STATUS + hisifd->sec_rch_idx * 0x4);
	if ((tmp & 0x10) != 0x10) {
		HISI_FB_ERR("rch%d not in idle state, rch_status=0x%x !\n", hisifd->sec_rch_idx, tmp);
		hisifd->set_reg(hisifd->rdma_base + CH_SW_END_REQ, 0x1, 32, 0);
		do {
			SRE_SwMsleep(1);
			tmp = inp32(hisifd->rdma_base + CH_SW_END_REQ);
		} while (tmp);
	}

	hisifd->set_reg(hisifd->rdma_base + CH_REG_DEFAULT, 0x1, 32, 0);
	hisifd->set_reg(hisifd->rdma_base + CH_REG_DEFAULT, 0x0, 32, 0);
	// clear config
	hisifd->set_reg(hisifd->mctl_base + MCTL_CTL_CLEAR, 0x1, 1, 0);
	HISI_FB_DEBUG("exit !\n");
}


void dss_registe_base_dma_cb(struct dss_dma_cb *dma_cb)
{
	HISI_ERR_CHECK_NO_RETVAL((dma_cb == NULL), "dma_cb is NULL\n");

	dma_cb->exit_display_rdma_config = dss_exit_display_rdma_config;
	dma_cb->display_rdma_config = dss_display_rdma_config;
	dma_cb->check_rch_idle = dss_check_rch_idle;

	dss_registe_platform_dma_cb(dma_cb);
}



