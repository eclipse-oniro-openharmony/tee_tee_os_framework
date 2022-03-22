/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display channel data array
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */


#ifndef HISI_DSS_CHANNEL_DATA_H
#define HISI_DSS_CHANNEL_DATA_H

#include "hisi_fb_sec.h"

// 980base: 970/980/990, 710base: 710/orlando, 9A0base: 9A0, denver base: denver/laguna/burbank
extern uint32_t g_dss_module_base[DSS_CHN_MAX_DEFINE][MODULE_CHN_MAX];
extern uint32_t g_dss_module_ovl_base[DSS_MCTL_IDX_MAX][MODULE_OVL_MAX];
extern uint32_t g_dss_chn_sid_num[DSS_CHN_MAX_DEFINE];
extern uint32_t g_dss_smmu_smrx_idx[DSS_CHN_MAX_DEFINE];

#endif

