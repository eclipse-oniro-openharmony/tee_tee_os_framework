/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display smmu registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "hisi_dss_smmu.h"

static void dss_smmu_set_smr(const struct hisifb_data_type *hisifd, uint8_t index, int securemode)
{
	if (securemode == SECURE_MODE) {
		hisifd->set_reg(hisifd->smmu_base + SMMU_SMRx_S + index * 0x4, 0x6, 3, 0);
	} else if (securemode == PROTECTED_MODE) {
		hisifd->set_reg(hisifd->smmu_base + SMMU_SMRx_P + index * 0x4, 0x1, 1, 0);
	} else { // NON_SECURE_MODE
		hisifd->set_reg(hisifd->smmu_base + SMMU_SMRx_S + index * 0x4, 0x3, 3, 0);
		hisifd->set_reg(hisifd->smmu_base + SMMU_SMRx_P + index * 0x4, 0x0, 1, 0);
	}
}


static void dss_smmu_set_rld(const struct hisifb_data_type *hisifd, uint8_t index)
{
	if (index < 32) {
		hisifd->set_reg(hisifd->smmu_base + SMMU_RLD_EN0_S, 0x1, 1, index);
		hisifd->set_reg(hisifd->smmu_base + SMMU_RLD_EN0_P, 0x1, 1, index);
		hisifd->set_reg(hisifd->smmu_base + SMMU_RLD_EN0_NS, 0x1, 1, index);
	} else {
		hisifd->set_reg(hisifd->smmu_base + SMMU_RLD_EN1_S, 0x1, 1, (index - 32));
		hisifd->set_reg(hisifd->smmu_base + SMMU_RLD_EN1_P, 0x1, 1, (index - 32));
		hisifd->set_reg(hisifd->smmu_base + SMMU_RLD_EN1_NS, 0x1, 1, (index - 32));
	}
}

static int dss_smmu_config(const struct hisifb_data_type *hisifd, int securemode)
{
	uint32_t idx = 0;
	uint32_t i;

	HISI_ERR_CHECK_RETURN((hisifd->sec_rch_idx >= DSS_CHN_MAX_DEFINE), -1, "rch_idx is invalid!\n");

	HISI_FB_DEBUG("+\n");

	for (i = 0; i < g_dss_chn_sid_num[hisifd->sec_rch_idx]; i++) {
		idx = g_dss_smmu_smrx_idx[hisifd->sec_rch_idx] + i;
		dss_smmu_set_smr(hisifd, idx, securemode);
		dss_smmu_set_rld(hisifd, idx);
	}

	HISI_FB_DEBUG("-\n");
	return 0;
}

void dss_registe_base_smmu_cb(struct dss_smmu_cb *smmu_cb)
{
	HISI_ERR_CHECK_NO_RETVAL((smmu_cb == NULL), "smmu_cb is NULL\n");

	smmu_cb->smmu_set_smr = dss_smmu_set_smr;
	smmu_cb->smmu_set_rld = dss_smmu_set_rld;
	smmu_cb->smmu_config = dss_smmu_config;

	dss_registe_platform_smmu_cb(smmu_cb);
}
