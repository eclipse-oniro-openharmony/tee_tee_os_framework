/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hieps plat config.
 * Author : z00452790, zhaohaisheng@huawei.com
 * Create: 2019/09/12
 */


#ifndef __HIEPS_POWERCTRL_PLAT_H__
#define __HIEPS_POWERCTRL_PLAT_H__

#include <types.h>

enum hieps_profile_type {
	PROFILE_TYPE_0 = 0, /* profile:0 0.8V 320M */
	PROFILE_TYPE_1 = 1, /* profile:1 0.7V 240M */
	PROFILE_TYPE_2 = 2, /* profile:2 0.6V 138M */
	PROFILE_TYPE_MAX,
};

enum hieps_clksrc_type {
	HIEPS_PPLL0 = 1,
	HIEPS_19M   = 2,
	HIEPS_PPLL2 = 4,
	HIEPS_PPLL3 = 8,
	HIEPS_MAX_CLKSYS,
};

enum hieps_clk_frequency {
	HIEPS_PROFILE0_320 = 320,
	HIEPS_PROFILE1_240 = 240,
	HIEPS_PROFILE2_138 = 138,
}; /* unit MHZ */

enum hieps_clk_div_clk {
	HIEPS_CLK_DIV1 = 0,
	HIEPS_CLK_DIV2 = 1,
	HIEPS_CLK_DIV3 = 2,
	HIEPS_CLK_DIV4 = 3,
	HIEPS_CLK_DIV5 = 4,
	HIEPS_CLK_DIV6 = 5,
	HIEPS_CLK_DIV7 = 6,
	HIEPS_CLK_DIV8 = 7,
};

enum hieps_phase_type {
	HIEPS_ROM_PHASE = 0x3A4B5C6D,
	HIEPS_BSP_PHASE = 0xC5B4A392,
	HIEPS_MAX_PHASE,
};

struct hieps_power_param_type {
	enum hieps_clk_frequency hieps_bsp_clk;
	enum hieps_clk_div_clk hieps_bsp_div;
};

uint32_t hieps_select_clk_source(void);
uint32_t hieps_set_clk_div(uint32_t clkdiv);
void hieps_set_low_temperature_flag(uint32_t flag);
uint32_t hieps_get_low_temperature_flag(void);
uint32_t hieps_cfg_clk_div(const uint32_t profile);

#endif /* __HIEPS_POWERCTRL_PLAT_H__ */
