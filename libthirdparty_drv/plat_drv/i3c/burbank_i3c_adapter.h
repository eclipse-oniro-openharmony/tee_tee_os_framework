/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: teeos i3c adapter,differentiate platform differences
 * Author: hisilicon
 * Create: 2020-11-5
 */
#ifndef __BURBANK_I3C_ADAPTER_H__
#define __BURBANK_I3C_ADAPTER_H__

#include "i3c.h"

struct i3c_adapter i3c_adaps[] = {
	[0]  = {
		.bus_num = I3C4,
		.clk_rate = 163000,
		.baseaddr = SOC_ACPU_I3C4_BASE_ADDR,
		.clk_bit = 0,
		.clk_en_reg = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x470,
		.clk_dis_reg = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x474,
		.clk_stat_reg = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x478,
		.rst_bit = 24,
		.rst_en_reg = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x90,
		.rst_dis_reg = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x94,
		.rst_stat_reg = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x98,
		.domain = I3C_AP_DOMAIN,
		.tzpc_flag = NEED_SWITCH_SEC_FLAG,
		.tzpc_data.tzpc_map.tzpc_idx = TZ_I3C4,
		.scl_iomux_gpio = 255,
		.sda_iomux_gpio = 256,
		.iomux_i3c_val = 4,
		.iomux_normal_val = 0,
		.scl_pp_freq = 1000,
		.scl_od_freq = 400,
	},
};

#endif
