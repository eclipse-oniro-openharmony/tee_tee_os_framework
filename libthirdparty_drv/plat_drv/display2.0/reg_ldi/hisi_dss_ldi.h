/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display ldi registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_DSS_LDI_H
#define HISI_DSS_LDI_H

// 980base-970/980/710/orlando, 990base-990/9A0/denver/laguna/burbank
#include "channel_data/hisi_dss_channel_data.h"

struct dss_ldi_cb {
	void (*single_frame_update)(struct hisifb_data_type *hisifd);
	void (*vactive0_dump)(struct hisifb_data_type *hisifd);
	int (*clear_irq)(struct hisifb_data_type *hisifd);
	void (*mcu_interrupt_mask)(struct hisifb_data_type *hisifd);
	void (*mcu_interrupt_unmask)(struct hisifb_data_type *hisifd);
};

void dss_registe_base_ldi_cb(struct dss_ldi_cb *ldi_cb);
bool is_dsi1_te1(struct hisifb_data_type *hisifd);

#define dss_registe_platform_ldi_cb(ldi_cb)

#endif

