/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: teeos i3c adapter,differentiate platform differences
 * Author: hisilicon
 * Create: 2019-07-04
 */
#ifndef __KIRIN990_I3C_ADAPTER_H__
#define __KIRIN990_I3C_ADAPTER_H__

#include "i3c.h"

struct i3c_adapter i3c_adaps[] = {
	[0]  = {
		.bus_num = I3C4,
		.clk_rate = 166000,
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
#if defined(WITH_KIRIN990_CS2)
		.scl_iomux_gpio = 277,
		.sda_iomux_gpio = 278,
#else
		.scl_iomux_gpio = 276,
		.sda_iomux_gpio = 277,
#endif
		.iomux_i3c_val = 1,
		.iomux_normal_val = 1,
		.dma_rx_num = 18,
		.dma_tx_num = 19,
		.scl_pp_freq = 1000,
		.scl_od_freq = 400,
	},
};

#endif
