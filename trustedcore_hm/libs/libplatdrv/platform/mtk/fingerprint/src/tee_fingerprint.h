/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: MTK TEE Fingerprint Header File
 * Author: tangjianbo
 * Create: 2020-01-21
 */
#ifndef TEE_FINGERPRINT_H
#define TEE_FINGERPRINT_H

#include "stdint.h"
#include <sre_typedef.h>

#define EINTR  10
#define EFAULT 14
enum {
    FPC_AUTHORIZE_ERROR = 11,
    FPC_GPIO_INIT_ERROR,
};

struct register_addr_fingerprint_gpio {
    unsigned int register_addr_fingerprint_reset;
    unsigned int register_addr_fingerprint_irq;
    unsigned int register_addr_fingerprint_spi_cs;
    unsigned int register_addr_fingerprint_reset_ud;
    unsigned int register_addr_fingerprint_irq_ud;
    unsigned int register_addr_fingerprint_spi_cs_ud;
    unsigned int register_addr_fingerprint_moduleid;
    unsigned int register_addr_fingerprint_spi_freq;
    unsigned int register_addr_fingerprint_fpc2050;
    unsigned int spi_num;
    unsigned char product_id;
};

enum command_info {
    FINGERPRINT_SPI_INIT = 1,
    FINGERPRINT_READ_INT_STATUS,
    FINGERPRINT_RESET_SENSOR,
    FINGERPRINT_READ_MODULE_STATUS,
    FINGERPRINT_GET_PRODUCT_INFO,
    FINGERPRINT_GET_SENSORHUB_CAC_IMG,
    FINGERPRINT_GET_SENSORHUB_FALLBACK_IMG,
    FINGERPRINT_SET_RESET_PIN_DIRECTION,
    FINGERPRINT_SET_IRQ_PIN_PULLTYPE,
    FINGERPRINT_DISABLE_IRQ = 10,
    FINGERPRINT_DEV2_READ_INT_STATUS,
    FINGERPRINT_DEV2_RESET_SENSOR,
};

enum module_value {
    MODULE_OFILM = 0x0000,
    MODULE_CT = 0x0001,
    MODULE_LITON_FOR_JAZZ = 0x0100,
    MODULE_CT_FOR_JAZZ = 0x0101,
};

struct fp_cmd_info {
    unsigned char command;
    unsigned char module_value;
    unsigned char irq_pin_value;
    unsigned char reset_pin_value;
    unsigned char product_value;
    uint64_t sensorhub_img_buf;
    unsigned int sensorhub_img_size;
    int32_t sensorhub_fail_img_cnt;
    int32_t sensorhub_anti_touch_cnt;
    int32_t max_score;
    unsigned char reset_pin_direction;
    unsigned char irq_pin_pull_type;
};

struct spi_transaction_info {
    uint64_t reg_addr;
    uint64_t buf_addr;
    unsigned int reg_len;
    unsigned int buf_len;
};

struct fp_dts_conf {
    u16 head_check;
    u16 product_id;
    u8 spi_bus;
    u8 sensor_type;
    u8 resv[8]; /* Reserve 8 bytes */
    u16 tail_check;
} __attribute__((__packed__));

enum dts_cfg_index {
    INDEX_SENSOR_TYPE = 0,
    INDEX_SPI_BUS,
    INDEX_HEAD_CHECK_LOW,
    INDEX_HEAD_CHECK_HIGH,
    INDEX_PRODUCT_ID_LOW,
    INDEX_PRODUCT_ID_HIGH,
    INDEX_TAIL_CHECK_LOW,
    INDEX_TAIL_CHECK_HIGH,
};

/* Data for the three images. */
int init_capture(void *setup);

/* Captures and reads three images from the sensor. */
int read_image(void *image);

int driver_fingerprint_command(struct fp_cmd_info *command_info);
int driver_spi_full_duplex(struct spi_transaction_info *p_write_info, struct spi_transaction_info *p_read_info);
int driver_spi_full_duplex_with_speed(struct spi_transaction_info *p_write_info,
                                      struct spi_transaction_info *p_read_info, int speed);
int driver_read_image_from_sensorhub(uint8_t *image_buf, uint32_t image_size, uint8_t image_type);
int spi_tui_mutex(void);

#endif
