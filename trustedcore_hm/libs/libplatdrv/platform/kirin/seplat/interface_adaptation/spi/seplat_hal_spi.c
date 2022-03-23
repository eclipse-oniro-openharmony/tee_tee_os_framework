/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: Provides abstract SPI interfaces for the data link layer.
 * Create: 2020/12/05
 */

#include "seplat_hal_spi.h"
#include "spi.h"
#include "types.h"
#include "seplat_hal_gpio.h"
#include "seplat_hal_log.h"
#include "gpio.h"
#include "hisi_boot.h"
#include "securec.h"
#include "seplat_errno.h"
#include "seplat_common.h"
#include "dl_common.h"
#include "seplat_define.h"

#define SEPLAT_THIS_MODULE SEPLAT_MODULE_HAL_SPI
#define SEPLAT_ERROR_TAG "[SEPLAT_SPI]"

#define HAL_SPI_MAX_DATA_LEN  260

#define HAL_SPI_TX_ENABLE     1
#define HAL_SPI_SUPPORT_HZ    14000000
#define HAL_SPI_CS_GPIO_FUNC  0
#define HAL_SPI_RESUME_DSLEEP_DELAY_TIME  13000 /* 13ms */
#define HAL_SPI_RESUME_SLEEP_DELAY_TIME   6000 /* 5ms */

enum spi_cs_status {
    SPI_CS_ENABLE,
    SPI_CS_DISABLE,
};

enum {
    HAL_HOST_SPI_0 = 0,
    HAL_HOST_SPI_1,
    HAL_HOST_SPI_2,
    HAL_HOST_SPI_3,
    HAL_HOST_SPI_4,
    HAL_HOST_SPI_5,
};

struct hal_spi_polling_byte {
    uint8_t null_byte;
    uint8_t sleep_byte;
};

struct hal_spi_config {
    uint32_t spi_id;
    uint32_t spi_base;
    uint32_t spi_cs_gpio;
    uint32_t spi_cs_mode;
};

struct hal_spi_config g_hal_host_spi_config_table[] = {
    { .spi_id = HAL_HOST_SPI_1,
    .spi_base = SEPLAT_LINK_TO_AP_SPI_1,
    .spi_cs_gpio = SEPLAT_LINK_TO_AP_SPI_1_CS_GPIO,
    .spi_cs_mode = SEPLAT_LINK_TO_AP_SPI_1_CS_MODE
    },
};

static struct hal_spi_config g_seplat_spi0 = {0};

static struct hal_spi_polling_byte g_spi0_polling_byte = {
    .null_byte = COS_NULL_BYTE, .sleep_byte = COS_SLEEP_BYTE
};

static void hal_spi_cs_control_stub(uint32_t ctrl)
{
    UNUSED(ctrl);
}

static void hal_spi_cs_set(u32 gpio_id, u32 control)
{
    (void)hal_gpio_set_direction(gpio_id, HAL_GPIO_OUTPUT);
    if (control == SPI_CS_DISABLE)
        (void)hal_gpio_set_value(gpio_id, HAL_GPIO_HIGH_VALUE);
    else
        (void)hal_gpio_set_value(gpio_id, HAL_GPIO_LOW_VALUE);
}

static int32_t spi_transfer_adapter(const uint8_t *txbuf, uint8_t *rxbuf, uint32_t len, const uint32_t chip_addr)
{
    struct spi_transfer t;
    struct spi_message m;
    int ret;
    struct spi_config_chip chip_info = {
        .hierarchy = SSP_MASTER,
        .slave_tx_disable = HAL_SPI_TX_ENABLE,
        .cs_control = hal_spi_cs_control_stub,
    };
    struct spi_device spi = {
        .max_speed_hz = HAL_SPI_SUPPORT_HZ,
        .mode = SPI_MODE_0,
        .bits_per_word = 8,
        .controller_data = &chip_info,
    };

    t.tx_buf = txbuf;
    t.rx_buf = rxbuf;
    t.len = len;
    t.delay_usecs = 0;
    t.cs_change = 1;

    m.transfers = &t;
    m.transfer_num = 1;
    m.actual_length = 0;
    m.status = 0;

    ret = hisi_spi_init(chip_addr, &spi);
    if (ret != SPI_OK) {
        hal_print_error("spi init fail %x\n", ret);
        return ret;
    }

    ret = hisi_spi_polling_transfer(chip_addr, &m);
    if (ret != SPI_OK) {
        hal_print_error("polling transfer error: ret=[%x]\n", ret);
        hisi_spi_exit(chip_addr);
        return ret;
    }

    hisi_spi_exit(chip_addr);
    return SEPLAT_OK;
}

int32_t hal_spi0_entry(void)
{
    hal_spi_cs_set(g_seplat_spi0.spi_cs_gpio, SPI_CS_ENABLE);

    return SEPLAT_OK;
}

int32_t hal_spi0_exit(void)
{
    hal_spi_cs_set(g_seplat_spi0.spi_cs_gpio, SPI_CS_DISABLE);

    return SEPLAT_OK;
}

int32_t hal_spi0_send(uint8_t *buf, uint32_t len, uint32_t is_polling)
{
    int32_t ret;
    uint8_t rsp[HAL_SPI_MAX_DATA_LEN] = {0};

    IF_NULL_RETURN(buf, SEPLAT_ERRCODE(SEPLAT_SPI0_SEND_BUF_NULL));

    if (len > HAL_SPI_MAX_DATA_LEN) {
        hal_print_error("%s len too long %u\n", __func__, len);
        return SEPLAT_ERRCODE(SEPLAT_SPI0_SEND_BUF_TOO_SMALL);
    }

    ret = spi_transfer_adapter(buf, rsp, len, SOC_ACPU_SPI1_BASE_ADDR);
    if (ret != SEPLAT_OK) {
        hal_print_error("%s fail ret=%d\n", __func__, ret);
        return ret;
    }

    if (is_polling != HAL_SPI_POLLING)
        return SEPLAT_OK;
    if (rsp[0] == g_spi0_polling_byte.sleep_byte)
        return HAL_COMMON_CHANNEL_NACK;

    if (rsp[0] == g_spi0_polling_byte.null_byte)
        return SEPLAT_OK;
    return SEPLAT_ERRCODE(SEPLAT_SPI0_SEND_CHANNEL_DIRTY_DATA);
}

int32_t hal_spi0_recv(uint8_t *buf, uint32_t len, uint32_t is_polling)
{
    int32_t ret;
    uint8_t req[HAL_SPI_MAX_DATA_LEN] = {0};

    IF_NULL_RETURN(buf, SEPLAT_ERRCODE(SEPLAT_SPI0_RECV_BUF_NULL));

    if (len > HAL_SPI_MAX_DATA_LEN) {
        hal_print_error("%s len too long %u\n", __func__, len);
        return SEPLAT_ERRCODE(SEPLAT_SPI0_RECV_BUF_TOO_SMALL);
    }

    ret = spi_transfer_adapter(req, buf, len, SOC_ACPU_SPI1_BASE_ADDR);
    if (ret != SEPLAT_OK) {
        hal_print_error("spi_transfer_adapter fail ret=%d\n", ret);
        return ret;
    }
    if (is_polling != HAL_SPI_POLLING)
        return SEPLAT_OK;
    if (buf[0] == g_spi0_polling_byte.null_byte)
        return HAL_COMMON_CHANNEL_NACK;

    return SEPLAT_OK;
}

void hal_spi0_flush(uint32_t len)
{
    int32_t ret;
    uint8_t flush_buf[HAL_SPI_MAX_DATA_LEN] = {0};

    if (len > HAL_SPI_MAX_DATA_LEN)
        ret = hal_spi0_send(flush_buf, HAL_SPI_MAX_DATA_LEN, false);
    else
        ret = hal_spi0_send(flush_buf, len, false);
    if (ret != SEPLAT_OK)
        hal_print_error("spi0 flush error %x\n", ret);
}

int32_t hal_spi0_init(uint32_t spi_id)
{
    uint32_t i;
    int32_t ret;

    for (i = 0; i < ARRAY_SIZE(g_hal_host_spi_config_table); i++) {
        if (spi_id == g_hal_host_spi_config_table[i].spi_id)
            break;
    }
    if (i >= ARRAY_SIZE(g_hal_host_spi_config_table)) {
        hal_print_error("%s spi_id err %u\n", __func__, spi_id);
        return SEPLAT_ERRCODE(SEPLAT_SPI0_INIT_ID_ERR);
    }

    g_seplat_spi0 = g_hal_host_spi_config_table[i];

    ret = hal_gpio_set_mode(g_seplat_spi0.spi_cs_gpio, g_seplat_spi0.spi_cs_mode);
    if (ret != SEPLAT_OK) {
        hal_print_error("%s %u set mode fail\n", __func__, spi_id);
        return ret;
    }
    hal_spi_cs_set(g_seplat_spi0.spi_cs_gpio, SPI_CS_DISABLE);
    return SEPLAT_OK;
}

void hal_spi0_set_polling_byte(uint32_t null_byte, uint32_t sleep_byte)
{
    g_spi0_polling_byte.null_byte = null_byte;
    g_spi0_polling_byte.sleep_byte = sleep_byte;
}

int32_t hal_spi1_entry(void)
{
    return SEPLAT_OK;
}

int32_t hal_spi1_exit(void)
{
    return SEPLAT_OK;
}

int32_t hal_spi1_send(uint8_t *buf, uint32_t len, uint32_t is_polling)
{
    UNUSED(buf);
    UNUSED(len);
    UNUSED(is_polling);
    return SEPLAT_OK;
}

int32_t hal_spi1_recv(uint8_t *buf, uint32_t len, uint32_t is_polling)
{
    UNUSED(buf);
    UNUSED(len);
    UNUSED(is_polling);
    return SEPLAT_OK;
}

void hal_spi1_flush(uint32_t len)
{
    UNUSED(len);
}

int32_t hal_spi1_init(uint32_t spi_id)
{
    UNUSED(spi_id);
    return SEPLAT_OK;
}

void hal_spi1_set_polling_byte(void)
{
}
