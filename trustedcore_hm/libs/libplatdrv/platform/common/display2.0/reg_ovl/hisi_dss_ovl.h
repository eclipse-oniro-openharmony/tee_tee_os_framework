/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display ovl registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_DSS_OVL_H
#define HISI_DSS_OVL_H

// 710base-710/orlando, 980base-970/980/990/9A0/denver/laguna/burbank
#include "channel_data/hisi_dss_channel_data.h"

struct dss_ovl_cb {
	void (*ovl_layer_config)(struct hisifb_data_type *hisifd, dss_layer_t *layer);
	void (*ovl_config_clear)(struct hisifb_data_type *hisifd);
};

void dss_registe_base_ovl_cb(struct dss_ovl_cb *ovl_cb);

#define dss_registe_platform_ovl_cb(ovl_cb)

#endif


