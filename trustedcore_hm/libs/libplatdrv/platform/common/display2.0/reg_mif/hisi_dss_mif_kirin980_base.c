/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display mif registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "hisi_dss_mif.h"

static void dss_mif_config(const struct hisifb_data_type *hisifd, int securemode)
{
	HISI_FB_DEBUG("+\n");
	if (securemode != NON_SECURE_MODE) {
		hisifd->set_reg(hisifd->mif_ch_base + MIF_CTRL1, 0x00000020, 32, 0);
		hisifd->set_reg(hisifd->mif_ch_base + MIF_CTRL2, 0x0, 32, 0);
		hisifd->set_reg(hisifd->mif_ch_base + MIF_CTRL3, 0x0, 32, 0);
		hisifd->set_reg(hisifd->mif_ch_base + MIF_CTRL4, 0x0, 32, 0);
		hisifd->set_reg(hisifd->mif_ch_base + MIF_CTRL5, 0x0, 32, 0);
	}
	HISI_FB_DEBUG("-\n");
}

void dss_registe_base_mif_cb(struct dss_mif_cb *mif_cb)
{
	HISI_ERR_CHECK_NO_RETVAL((mif_cb == NULL), "mif_cb is NULL\n");

	mif_cb->mif_config = dss_mif_config;

	dss_registe_platform_mif_cb(mif_cb);
}
