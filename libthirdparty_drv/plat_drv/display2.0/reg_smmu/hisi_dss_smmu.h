/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display smmu registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_DSS_SMMU_H
#define HISI_DSS_SMMU_H

// 980base-980/990/9A0/orlando/denver/laguna/burbank, platform-710/970
#include "channel_data/hisi_dss_channel_data.h"

struct dss_smmu_cb {
	void (*smmu_set_smr)(const struct hisifb_data_type *hisifd, uint8_t index, int securemode);
	void (*smmu_set_rld)(const struct hisifb_data_type *hisifd, uint8_t index);
	int (*smmu_config)(const struct hisifb_data_type *hisifd, int securemode);
};

void dss_registe_base_smmu_cb(struct dss_smmu_cb *smmu_cb);

#if defined(CONFIG_DSS_TYPE_KIRIN710) || defined(CONFIG_DSS_TYPE_KIRIN970) || defined(CONFIG_DSS_TYPE_BALTIMORE)
void dss_registe_platform_smmu_cb(struct dss_smmu_cb *smmu_cb);
#else
#define dss_registe_platform_smmu_cb(smmu_cb)
#endif


#endif


