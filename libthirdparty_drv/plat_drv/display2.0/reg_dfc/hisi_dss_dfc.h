/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display dfc registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_DSS_DFC_H
#define HISI_DSS_DFC_H

// platform-710/orlando, 980base-970/980/990/9A0/denver/laguna/burbank
#include "channel_data/hisi_dss_channel_data.h"

struct dss_dfc_cb {
	void (*display_rdfc_config)(struct hisifb_data_type *hisifd, dss_layer_t *layer);
	void (*display_extra_rdfc_config)(struct hisifb_data_type *hisifd);
};

void dss_registe_base_dfc_cb(struct dss_dfc_cb *dfc_cb);

#if defined(CONFIG_DSS_TYPE_KIRIN710) || defined(CONFIG_DSS_TYPE_ORLANDO)
void dss_registe_platform_dfc_cb(struct dss_dfc_cb *dfc_cb);
#else
#define dss_registe_platform_dfc_cb(dfc_cb)
#endif

#endif
