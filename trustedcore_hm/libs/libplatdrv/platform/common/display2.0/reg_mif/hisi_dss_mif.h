/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display mif registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_DSS_MIF_H
#define HISI_DSS_MIF_H

// 980base-970/980/990/9A0/710/orlando/denver/laguna/burbank
#include "channel_data/hisi_dss_channel_data.h"

struct dss_mif_cb {
	void (*mif_config)(const struct hisifb_data_type *hisifd, int securemode);
};

void dss_registe_base_mif_cb(struct dss_mif_cb *mif_cb);

#define dss_registe_platform_mif_cb(mif_cb)

#endif

