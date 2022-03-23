/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: SPI regulator config.
 * Create: 2018-06-11
 */
#ifndef __SPI_CONFIG_KIRIN710_H__
#define __SPI_CONFIG_KIRIN710_H__

#include "spi_config_common.h"

static struct spi_resource spi_res[] = {
	[0] = {
		.bus_id = 1,
		.base = 0xFDF08000,
		.spi_clk_bit = 9,
		.reg_clk_enable = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x20,
		.reg_clk_disable = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x24,
		.reg_clk_status = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x28,
		.spi_clk_gate_bit = 13,
		.reg_clk_gate_enable = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x0F4,
		.spi_reset_bit = 9,
		.reg_reset_enable = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x78,
		.reg_reset_disable = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x7C,
		.reg_reset_status = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x80,
		.clk_rate = 41000000,
		.domain = SPI_AP_DOMAIN,
		.tzpc_flag = NEED_SWITCH_SEC_FLAG,
		.tzpc_data.tzpc_map.tzpc_idx = TZ_SPI1,

		.gpios[0] = {
			.gpio = 7,
			.function[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_M1,
			.function[SPI_GPIO_CFG_IDLE] = GPIOMUX_M0,
			.pulltype[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_NOPULL,
			.pulltype[SPI_GPIO_CFG_IDLE] = GPIOMUX_NOPULL,
		},
		.gpios[1] = {
			.gpio = 8,
			.function[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_M1,
			.function[SPI_GPIO_CFG_IDLE] = GPIOMUX_M0,
			.pulltype[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_NOPULL,
			.pulltype[SPI_GPIO_CFG_IDLE] = GPIOMUX_NOPULL,
		},
		.gpios[2] = {
			.gpio = 9,
			.function[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_M1,
			.function[SPI_GPIO_CFG_IDLE] = GPIOMUX_M0,
			.pulltype[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_NOPULL,
			.pulltype[SPI_GPIO_CFG_IDLE] = GPIOMUX_NOPULL,
		},
		.spi_hw.hw_valid = SPI_HARDWARE_MUTEX_VALID,
		.spi_hw.lock_id = 27,
		.spi_req_no.is_valid = SPI_DMA_REQ_NO_INVALID,
	},
	[1] = {
		.bus_id = 2,
		.base = 0xFFD68000,
		.spi_clk_bit = 30,
		.reg_clk_enable = SOC_ACPU_IOMCU_CONFIG_BASE_ADDR + 0x010,
		.reg_clk_disable = SOC_ACPU_IOMCU_CONFIG_BASE_ADDR + 0x014,
		.reg_clk_status = SOC_ACPU_IOMCU_CONFIG_BASE_ADDR + 0x018,
		.spi_clk_gate_bit = 0,
		.reg_clk_gate_enable = 0,
		.spi_reset_bit = 30,
		.reg_reset_enable = SOC_ACPU_IOMCU_CONFIG_BASE_ADDR + 0x020,
		.reg_reset_disable = SOC_ACPU_IOMCU_CONFIG_BASE_ADDR + 0x024,
		.reg_reset_status = SOC_ACPU_IOMCU_CONFIG_BASE_ADDR + 0x028,
		.clk_rate = 130000000,
		.domain = SPI_IOMCU_DOMAIN,
		.tzpc_flag = NO_NEED_SWITCH_SEC_FLAG,
		.tzpc_data.tzpc_info.addr = SOC_ACPU_IOMCU_CONFIG_BASE_ADDR,
		.tzpc_data.tzpc_info.offset = 0x100,
		.tzpc_data.tzpc_info.mask_bit = 5,

		.gpios[0] = {
			.gpio = 214,
			.function[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_M1,
			.function[SPI_GPIO_CFG_IDLE] = GPIOMUX_M0,
			.pulltype[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_NOPULL,
			.pulltype[SPI_GPIO_CFG_IDLE] = GPIOMUX_NOPULL,
		},
		.gpios[1] = {
			.gpio = 215,
			.function[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_M1,
			.function[SPI_GPIO_CFG_IDLE] = GPIOMUX_M0,
			.pulltype[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_NOPULL,
			.pulltype[SPI_GPIO_CFG_IDLE] = GPIOMUX_NOPULL,
		},
		.gpios[2] = {
			.gpio = 216,
			.function[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_M1,
			.function[SPI_GPIO_CFG_IDLE] = GPIOMUX_M0,
			.pulltype[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_NOPULL,
			.pulltype[SPI_GPIO_CFG_IDLE] = GPIOMUX_NOPULL,
		},
		.spi_hw.hw_valid = SPI_HARDWARE_MUTEX_VALID,
		.spi_hw.lock_id = 30,
		.spi_req_no.is_valid = SPI_DMA_REQ_NO_VALID,
		.spi_req_no.rx_req_no = 14,
		.spi_req_no.tx_req_no = 15,
	},
	[2] = {
		.bus_id = 4,
		.base = 0xFDF06000,
		.spi_clk_bit = 4,
		.reg_clk_enable = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x040,
		.reg_clk_disable = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x044,
		.reg_clk_status = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x048,
		.spi_clk_gate_bit = 13,
		.reg_clk_gate_enable = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x0F4,
		.spi_reset_bit = 15,
		.reg_reset_enable = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x060,
		.reg_reset_disable = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x064,
		.reg_reset_status = SOC_ACPU_PERI_CRG_BASE_ADDR + 0x068,
		.clk_rate = 41000000,
		.domain = SPI_AP_DOMAIN,
		.tzpc_flag = NO_NEED_SWITCH_SEC_FLAG,
		.tzpc_data.tzpc_map.tzpc_idx = TZ_SPI4,

		.gpios[0] = {
			.gpio = 214,
			.function[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_M4,
			.function[SPI_GPIO_CFG_IDLE] = GPIOMUX_M0,
			.pulltype[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_NOPULL,
			.pulltype[SPI_GPIO_CFG_IDLE] = GPIOMUX_NOPULL,
		},
		.gpios[1] = {
			.gpio = 215,
			.function[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_M4,
			.function[SPI_GPIO_CFG_IDLE] = GPIOMUX_M0,
			.pulltype[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_NOPULL,
			.pulltype[SPI_GPIO_CFG_IDLE] = GPIOMUX_NOPULL,
		},
		.gpios[2] = {
			.gpio = 216,
			.function[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_M4,
			.function[SPI_GPIO_CFG_IDLE] = GPIOMUX_M0,
			.pulltype[SPI_GPIO_CFG_DEFAULT] = GPIOMUX_NOPULL,
			.pulltype[SPI_GPIO_CFG_IDLE] = GPIOMUX_NOPULL,
		},
		.spi_hw.hw_valid = SPI_HARDWARE_MUTEX_VALID,
		.spi_hw.lock_id = 30,
		.spi_req_no.is_valid = SPI_DMA_REQ_NO_INVALID,
	},
};

#endif
