/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display smmu registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-11-06
 */

#include "hisi_dss_smmu.h"

static int dss_smmu_config(const struct hisifb_data_type *hisifd, int securemode)
{
	HISI_ERR_CHECK_RETURN((hisifd == NULL), -1, "hisifd is NULL\n");

	HISI_ERR_CHECK_RETURN((hisifd->sec_rch_idx >= DSS_CHN_MAX_DEFINE), -1, "rch_idx is invalid!\n");

	HISI_FB_DEBUG("+\n");

	if (securemode != NON_SECURE_MODE)
		hisifd->set_reg(hisifd->dss_base + DSS_VBIF0_AIF + MMU_ID_ATTR_7, 0x13F, 9, 0);
	else
		hisifd->set_reg(hisifd->dss_base + DSS_VBIF0_AIF + MMU_ID_ATTR_7, 0x0, 32, 0);

	HISI_FB_DEBUG("-\n");
	return 0;
}

void dss_registe_platform_smmu_cb(struct dss_smmu_cb *smmu_cb)
{
	HISI_ERR_CHECK_NO_RETVAL((smmu_cb == NULL), "smmu_cb is NULL\n");

	smmu_cb->smmu_config = dss_smmu_config;
}
