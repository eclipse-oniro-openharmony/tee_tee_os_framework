/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display ovl registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "hisi_dss_ovl.h"

static void dss_ovl_layer_config(struct hisifb_data_type *hisifd, dss_layer_t *layer)
{
	HISI_FB_DEBUG("enter!\n");

	hisifd->set_reg(hisifd->ovl_base + OVL_LAYER7_POS, ((layer->dst_rect.x) | (layer->dst_rect.y << 16)), 32, 0);
	hisifd->set_reg(hisifd->ovl_base + OVL_LAYER7_SIZE, (DSS_WIDTH(layer->dst_rect.x + layer->dst_rect.w) |
		(DSS_HEIGHT(layer->dst_rect.y + layer->dst_rect.h) << 16)), 32, 0);

	hisifd->set_reg(hisifd->ovl_base + OVL_LAYER7_ALPHA_MODE, 0x4000, 32, 0);
	hisifd->set_reg(hisifd->ovl_base + OVL_LAYER7_ALPHA_A, 0x3ff03ff, 32, 0);
	hisifd->set_reg(hisifd->ovl_base + OVL_LAYER7_CFG, 0x1, 1, 0);

	HISI_FB_DEBUG("exit!\n");
}

static void dss_ovl_config_clear(struct hisifb_data_type *hisifd)
{
	HISI_ERR_CHECK_NO_RETVAL((hisifd->sec_rch_idx >= DSS_CHN_MAX_DEFINE), "sec_rch_idx is invalid\n");

	hisifd->set_reg(hisifd->rdma_base + CH_REG_DEFAULT, 0x1, 32, 0);
	hisifd->set_reg(hisifd->rdma_base + CH_REG_DEFAULT, 0x0, 32, 0);

	hisifd->set_reg(hisifd->ovl_base + OVL_LAYER7_POS, 0x0, 32, 0);
	hisifd->set_reg(hisifd->ovl_base + OVL_LAYER7_SIZE, 0x0, 32, 0);
	hisifd->set_reg(hisifd->ovl_base + OVL_LAYER7_ALPHA_MODE, 0x0, 32, 0);
	hisifd->set_reg(hisifd->ovl_base + OVL_LAYER7_ALPHA_A, 0x0, 32, 0);
	hisifd->set_reg(hisifd->ovl_base + OVL_LAYER7_CFG, 0x0, 1, 0);

	hisifd->set_reg(hisifd->rdma_base + CH_CTL, 0x0, 4, 0);
	hisifd->set_reg(hisifd->rdma_base + CH_SECU_EN, 0x0, 1, 0);

	hisifd->set_reg(hisifd->dss_base + g_dss_module_base[hisifd->sec_rch_idx][MODULE_MCTL_CHN_OV_OEN], 0x0, 1, 8);
	hisifd->set_reg(hisifd->mctrl_sys_base + MCTL_RCH_OV0_SEL1, 0xF, 4, 0);
}

void dss_registe_base_ovl_cb(struct dss_ovl_cb *ovl_cb)
{
	HISI_ERR_CHECK_NO_RETVAL((ovl_cb == NULL), "ovl_cb is NULL\n");

	ovl_cb->ovl_layer_config = dss_ovl_layer_config;
	ovl_cb->ovl_config_clear = dss_ovl_config_clear;

	dss_registe_platform_ovl_cb(mix_cb);
}


