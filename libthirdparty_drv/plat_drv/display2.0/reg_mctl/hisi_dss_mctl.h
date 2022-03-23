/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display mctl registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_DSS_MCTL_H
#define HISI_DSS_MCTL_H

// platform-710/orlando, 980base-970/980/990/9A0/denver/laguna/burbank
#include "channel_data/hisi_dss_channel_data.h"

struct dss_mctl_cb {
	void (*mctl_clear)(struct hisifb_data_type *hisifd);
	void (*mctl_mutex_lock)(struct hisifb_data_type *hisifd);
	void (*mctl_mutex_unlock)(struct hisifb_data_type *hisifd);
	void (*mctl_sec_flush_en)(struct hisifb_data_type *hisifd);
	void (*enter_display_mctl_config)(struct hisifb_data_type *hisifd);
	void (*enter_display_mctrl_config)(struct hisifb_data_type *hisifd);
	void (*exit_display_mctl_mctrl_config)(struct hisifb_data_type *hisifd);
};

void dss_registe_base_mctl_cb(struct dss_mctl_cb *mctl_cb);

#if defined(CONFIG_DSS_TYPE_KIRIN710) || defined(CONFIG_DSS_TYPE_ORLANDO)
void dss_registe_platform_mctl_cb(struct dss_mctl_cb *mctl_cb);
#else
#define dss_registe_platform_mctl_cb(mctl_cb)
#endif

#endif

