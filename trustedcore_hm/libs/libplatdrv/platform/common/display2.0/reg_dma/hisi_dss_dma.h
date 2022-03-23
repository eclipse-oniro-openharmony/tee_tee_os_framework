/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display dma registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_DSS_DMA_H
#define HISI_DSS_DMA_H

// 980base-970/980/990/9A0/710/orlando/denver/laguna/burbank
#include "channel_data/hisi_dss_channel_data.h"

struct dss_dma_cb {
	void (*exit_display_rdma_config)(struct hisifb_data_type *hisifd);
	void (*display_rdma_config)(struct hisifb_data_type *hisifd, dss_layer_t *layer);
	void (*check_rch_idle)(struct hisifb_data_type *hisifd);
};

void dss_registe_base_dma_cb(struct dss_dma_cb *dma_cb);

#define dss_registe_platform_dma_cb(dma_cb)

#endif


