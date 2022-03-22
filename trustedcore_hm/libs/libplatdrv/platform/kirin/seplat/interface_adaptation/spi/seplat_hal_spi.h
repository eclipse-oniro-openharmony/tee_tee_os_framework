/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: Provides abstract SPI interfaces for the data link layer. Must be synchronized with the HSE branch.
 * Create: 2020/12/05
 */
#ifndef HAL_SPI_H
#define HAL_SPI_H

#include "types.h"
#include "seplat_types.h"

#define HAL_SPI_POLLING     SEPLAT_TRUE
#define HAL_SPI_NOT_POLLING SEPLAT_FALSE

#define COS_NULL_BYTE             0xFF
#define COS_SLEEP_BYTE            0x00
#define ONCHIPROM_NULL_BYTE       0x00
#define ONCHIPROM_SLEEP_BYTE      0xFF

enum seplat_spi_err {
    SEPLAT_SPI0_SEND_BUF_NULL                = 0x1,
    SEPLAT_SPI0_SEND_BUF_TOO_SMALL           = 0x2,
    SEPLAT_SPI0_SEND_CHANNEL_DIRTY_DATA      = 0x3,
    SEPLAT_SPI0_RECV_BUF_NULL                = 0x4,
    SEPLAT_SPI0_RECV_BUF_TOO_SMALL           = 0x5,
    SEPLAT_SPI0_INIT_ID_ERR                  = 0x6,
};

/*
 * @breaf : Completes SPI data transmission.
 * @return SEPLAT_OK if success, other if failed.
 */
int32_t hal_spi0_entry(void);

int32_t hal_spi0_exit(void);

int32_t hal_spi0_send(uint8_t *buf, uint32_t len, uint32_t is_polling);

int32_t hal_spi0_recv(uint8_t *buf, uint32_t len, uint32_t is_polling);

void hal_spi0_flush(uint32_t len);

int32_t hal_spi0_init(uint32_t spi_id);

void hal_spi0_set_polling_byte(uint32_t null_byte, uint32_t sleep_byte);

int32_t hal_spi1_entry(void);

int32_t hal_spi1_exit(void);

int32_t hal_spi1_send(uint8_t *buf, uint32_t len, uint32_t is_polling);

int32_t hal_spi1_recv(uint8_t *buf, uint32_t len, uint32_t is_polling);

void hal_spi1_flush(uint32_t len);

int32_t hal_spi1_init(uint32_t spi_id);

void hal_spi1_set_polling_byte(void);

#endif
