/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: SPI device common structure.
 * Create: 2018-05-21
 */
#ifndef __SPI_CONFIG_COMMON_H__
#define __SPI_CONFIG_COMMON_H__

#include <gpio.h>
#include <tzpc.h>

#define SPI_AP_DOMAIN 0
#define SPI_IOMCU_DOMAIN 1

#define NO_NEED_SWITCH_SEC_FLAG 0
#define NEED_SWITCH_SEC_FLAG 1

#define SPI_GPIO_MAX_NUM 3

#define SPI_GPIO_CFG_DEFAULT 0
#define SPI_GPIO_CFG_IDLE 1

#define SPI_HARDWARE_MUTEX_INVALID 0
#define SPI_HARDWARE_MUTEX_VALID 1

#define SPI_DMA_REQ_NO_INVALID 0
#define SPI_DMA_REQ_NO_VALID 1

#define TIMEOUT_LOCAL 100000

struct gpio_spi_cfg_status {
	u32 gpio;
	u8 function[2];
	u8 pulltype[2];
};

struct tzpc_iomcu_domain_data {
	u32 addr;
	u32 offset;
	u32 mask_bit;
};

struct tzpc_ap_domain_map {
	u32 tzpc_idx;
};

struct spi_hardware {
	u32 hw_valid;
	u32 lock_id;
};

struct spi_dma_req_no {
	u32 is_valid;
	u32 rx_req_no;
	u32 tx_req_no;
};

struct spi_resource {
	u32 bus_id;
	u32 base;
	u32 spi_clk_bit;
	u32 reg_clk_enable;
	u32 reg_clk_disable;
	u32 reg_clk_status;
	u32 spi_clk_gate_bit;
	u32 reg_clk_gate_enable;
	u32 spi_reset_bit;
	u32 reg_reset_enable;
	u32 reg_reset_disable;
	u32 reg_reset_status;
	u32 clk_mask;
	u32 clk_rate;
	u32 domain;
	u32 tzpc_flag;
	union {
		struct tzpc_iomcu_domain_data tzpc_info;
		struct tzpc_ap_domain_map tzpc_map;
	} tzpc_data;
	struct gpio_spi_cfg_status
		gpios[SPI_GPIO_MAX_NUM]; /* spi_clk spi_di spi_do */
	struct spi_hardware spi_hw;
	struct spi_dma_req_no spi_req_no;
};

#endif
