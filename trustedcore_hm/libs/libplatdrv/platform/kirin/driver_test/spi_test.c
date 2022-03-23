/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: teeos spi driver test code
 *              This program is support for SPI test work.
 * Create: 2020-08-05
 */
#include <spi_test.h>
#include <spi.h>
#include <stdlib.h>
#include <drv_mem.h>
#include "libhwsecurec/securec.h"
#include <drv_module.h>
#include <tee_log.h>

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
#include "./../spi/spi_config_kirin970.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)
#include "./../spi/spi_config_kirin710.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680)
#include "./../spi/spi_config_kirin980.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#include "./../spi/spi_config_kirin990.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
#include "./../spi/spi_config_orlando.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#include "./../spi/spi_config_baltimore.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#include "./../spi/spi_config_denver.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_LAGUNA)
#include "./../spi/spi_config_laguna.h"
#else
#endif

#ifdef CONFIG_SUPPORT_DMA_STATIC_ADDR
#include "global_ddr_map.h"
#define DMA_TEST_TX_ADDR_OFFSET (310 * 1024)
#define DMA_TEST_RX_ADDR_OFFSET (315 * 1024)
#endif

#define MAX_SPEED_HZ_TEST 5000000

#define BITS_PER_WORD_8_TEST 8
#define SPI_TEST_TRANSFER_NUM 1

#define SPI_TEST_TX_ENABLE 1

#define SPI_DMA_TEST_ENABLE 1
#define SPI_DMA_TEST_DISABLE 0

#define SPI_BUF_TEST_LEN (4*1024)

#define SPI_TEST_VALUE3 3
#define SPI_TEST_VALUE0 0

#define SPI_TEST_PARAM_LEN 4
#define SPI_TEST_PARA_OFFSET 1

unsigned char input[SPI_BUF_TEST_LEN] = {0};
unsigned char output[SPI_BUF_TEST_LEN] = {0};

static int spi_dma_enable_test(const uint32_t chip_addr)
{
	struct spi_resource *sr = NULL;
	uint32_t max, index;

	max = sizeof(spi_res) / sizeof(struct spi_resource);

	for (index = 0; index < max; index++) {
		if (spi_res[index].base == chip_addr) {
			tloge(
				"spi bus-id is %d.\n", spi_res[index].bus_id);
			sr = &spi_res[index];
			break;
		}
	}

	if (sr == NULL) {
		tloge("spi can't get resource.\n");
		return SPI_DMA_TEST_DISABLE;
	}

	if (sr->spi_req_no.is_valid == SPI_DMA_REQ_NO_VALID)
		return SPI_DMA_TEST_ENABLE;
	else
		return SPI_DMA_TEST_DISABLE;
}

static void spi_test_xfer_init(
	struct spi_transfer *xfer, const uint32_t chip_addr)
{
	int ret_rx, ret_tx;
	unsigned char *rx_buf = NULL;
	unsigned char *tx_buf = NULL;

	if (spi_dma_enable_test(chip_addr) == SPI_DMA_TEST_ENABLE) {
#ifdef CONFIG_SUPPORT_DMA_STATIC_ADDR
		ret_rx = sre_mmap(HISI_RESERVED_FINGERPRINT_BASE +
			DMA_TEST_RX_ADDR_OFFSET, SPI_BUF_TEST_LEN,
			(uint32_t *)(&rx_buf), secure, non_cache);
		ret_tx = sre_mmap(HISI_RESERVED_FINGERPRINT_BASE +
			DMA_TEST_TX_ADDR_OFFSET, SPI_BUF_TEST_LEN,
			(uint32_t *)(&tx_buf), secure, non_cache);
		if (ret_rx || ret_tx) {
			tloge(" phy memory mmap failed !\n");
			return;
		}
#else
		rx_buf = input;
		tx_buf = output;
#endif
	} else {
		rx_buf = input;
		tx_buf = output;
	}
	ret_tx = memset_s(tx_buf, SPI_BUF_TEST_LEN, SPI_TEST_VALUE3,
		SPI_BUF_TEST_LEN);
	ret_rx = memset_s(rx_buf, SPI_BUF_TEST_LEN, SPI_TEST_VALUE0,
		SPI_BUF_TEST_LEN);
	if (ret_rx || ret_tx) {
		tloge("memset_s failed!ret_tx=[%d];ret_tx=[%d].\n",
			ret_tx, ret_rx);
		return;
	}

	xfer->tx_buf = (const void *) tx_buf;
	xfer->rx_buf = (void *) rx_buf;
	xfer->len = SPI_BUF_TEST_LEN;
}

static void spi_test_xfer_free(
	struct spi_transfer *xfer, const uint32_t chip_addr)
{
	if (spi_dma_enable_test(chip_addr) == SPI_DMA_TEST_ENABLE) {
#ifdef CONFIG_SUPPORT_DMA_STATIC_ADDR
		(void)sre_unmap((uint32_t)(uintptr_t)xfer->tx_buf,
			SPI_BUF_TEST_LEN);
		(void)sre_unmap((uint32_t)(uintptr_t)xfer->rx_buf,
			SPI_BUF_TEST_LEN);
#endif
	}
	xfer->tx_buf = NULL;
	xfer->rx_buf = NULL;
}

static int spi_test(const uint32_t chip_addr)
{
	struct spi_transfer xfer;
	struct spi_message msg;
	uint32_t index;
	int ret;

	struct spi_config_chip chip_info = {
		.hierarchy = SSP_MASTER,
		.slave_tx_disable = SPI_TEST_TX_ENABLE,
		.cs_control = null_cs_control,
	};

	struct spi_device spi = {
		.max_speed_hz = MAX_SPEED_HZ_TEST,
		.mode = SPI_MODE_0 | SPI_LOOP,
		.bits_per_word = BITS_PER_WORD_8_TEST,
		.controller_data = &chip_info,
	};

	spi_test_xfer_init(&xfer, chip_addr);
	msg.transfers = &xfer;
	msg.transfer_num = SPI_TEST_TRANSFER_NUM;

	ret = hisi_spi_init(chip_addr, &spi);
	if (ret) {
		spi_test_xfer_free(&xfer, chip_addr);
		tloge("spi_test_xfer_free!ret=[%d]\n", ret);
		return SPI_TEST_ERR;
	}

	ret = hisi_spi_dma_transfer(chip_addr, &msg);
	if (ret) {
		tloge("polling transfer error: ret=[%d]\n", ret);
		hisi_spi_exit(chip_addr);
		spi_test_xfer_free(&xfer, chip_addr);
		return SPI_TEST_ERR;
	}

	hisi_spi_exit(chip_addr);
	for (index = 0; index < SPI_BUF_TEST_LEN; index++) {
		if (*((unsigned char *)xfer.tx_buf + index)
			!= *((unsigned char *)xfer.rx_buf + index)) {
			tloge("%d, rx_buf=%x, tx_buf=%x dismach\n",
				index, *((unsigned char *)xfer.rx_buf + index),
				*((unsigned char *)xfer.tx_buf + index));
			break;
		}
	}
	if (index != SPI_BUF_TEST_LEN) {
		tloge(
			"********spi:0x%x test failed********\n", chip_addr);
		spi_test_xfer_free(&xfer, chip_addr);
		return SPI_TEST_ERR;
	}
	tloge("********spi:0x%x test ok********\n", chip_addr);
	spi_test_xfer_free(&xfer, chip_addr);

	return SPI_TEST_OK;
}

static int driver_spi_dep_test(void)
{
	uint32_t spi_cnt = sizeof(spi_res) / sizeof(struct spi_resource);
	int ret;
	uint32_t index;

	tloge("spi_driver_dep_test begin\n");
	for (index = 0; index < spi_cnt; index++) {
		tloge("index = %d\n", index);
		ret = spi_test(spi_res[index].base);
		tloge("index_%d end ret=%d\n", index, ret);
	}

	return SPI_TEST_OK;
}

uint32_t spi_driver_test(uint32_t num,
	const struct bus_test_para *parm_info)
{
	char *param[SPI_TEST_PARAM_LEN] = {0};
	uint32_t argv[SPI_TEST_PARAM_LEN] = {0};
	uint32_t index;
	int32_t ret;

	if ((!parm_info) || (num > SPI_TEST_PARAM_LEN)) {
		tloge("%s:Invalid input!\n", __func__);
		return SPI_TEST_ERR;
	}

	for (index = 0; index < SPI_TEST_PARAM_LEN; index++) {
		param[index] = (char *)&(parm_info->parm[index
			+ SPI_TEST_PARA_OFFSET]);
		argv[index] = (uint32_t)atoi(param[index]);
		tloge("%s: argv %d is %u\n", __func__, index, argv[index]);
	}

	switch (argv[SPI_PARA_0]) {
	case SPI_TEST_DEP:
		ret = driver_spi_dep_test();
		break;
	default:
		tloge("%s:Invalid index:%d!\n",
			__func__, argv[SPI_PARA_0]);
		return SPI_TEST_ERR;
	}

	if (ret != SPI_TEST_OK)
		tloge(" fail:%d!\n", ret);

	return ret;
}
