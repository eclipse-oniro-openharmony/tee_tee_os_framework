/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display different types registers mixed configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_DSS_MIX_H
#define HISI_DSS_MIX_H

// 980base-970/980/990/9A0/denver/laguna/burbank, 710base-710, 710base+platform-orlando
#include "channel_data/hisi_dss_channel_data.h"

struct dss_mix_cb {
	void (*dump_secure_display_reg)(struct hisifb_data_type *hisifd, bool is_once, bool need_shadow);
	void (*dump_reg_info)(struct hisifb_data_type *hisifd);
};

void dss_registe_base_mix_cb(struct dss_mix_cb *mix_cb);

#if defined(CONFIG_DSS_TYPE_ORLANDO)
void dss_registe_platform_mix_cb(struct dss_mif_cb *mix_cb);
#else
#define dss_registe_platform_mix_cb(mix_cb)
#endif

static inline void dss_dump_single_reg(const char *reg_name, uint32_t base_address, uint32_t offset_size)
{
	uint32_t count = 0;
	uint32_t step = 0;

	while (step < offset_size) {
		count = 0;
		HISI_FB_ERR("------ %s[0x%x]: \t", reg_name, base_address + step);
		do {
			HISI_FB_PRINTF(" 0x%x \t", inp32(base_address + step));
			step += 0x4; // a reg value is 4 bytes
			count++;
		} while (count < 4); // a line print 4 reg values
		HISI_FB_PRINTF("\n");
	}
}


#endif

