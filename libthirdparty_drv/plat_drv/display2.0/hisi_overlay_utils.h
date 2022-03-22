/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display main process
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_OVERLAY_UTILS_H
#define HISI_OVERLAY_UTILS_H

#include "hisi_fb_sec.h"

int hisi_secure_display_config(struct hisifb_data_type *hisifd, int sec_value);
int hisi_vactive0_start_config(struct hisifb_data_type *hisifd);
int hisi_frame_end_config(struct hisifb_data_type *hisifd);
int do_pan_display_config(struct hisifb_data_type *hisifd, dss_layer_t *layer);

#endif
