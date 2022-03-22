/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: fingerprint driver
 * Author: zhangfengxi
 * Create: 2017-8-22
 */

#ifndef TEE_FINGERPRINT_H
#define TEE_FINGERPRINT_H
#include "hisi_boot.h"
#include "stdint.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

enum {
    FPC_AUTHORIZE_ERROR = 11,
    FPC_GPIO_INIT_ERROR,
};

enum {
    FP_PARA_FIRST = 0,
    FP_PARA_SECOND,
    FP_PARA_THIRD
};

struct register_addr_fingerprint_gpio {
    unsigned int reg_addr_fp_reset;
    unsigned int reg_addr_fp_irq;
    unsigned int reg_addr_fp_spi_cs;
    unsigned int reg_addr_fp_reset_ud;
    unsigned int reg_addr_fp_irq_ud;
    unsigned int reg_addr_fp_spi_cs_ud;
    unsigned int reg_addr_fp_module_id;
    unsigned int reg_addr_fp_spi_freq;
    unsigned int reg_addr_fp_fpc2050;
    unsigned int reg_addr_fp_flash_rst_ud;
    unsigned int reg_addr_fp_clk_ud;
    unsigned int spi_num;
    u8 product_id;
    u8 dma_enable;
};

enum {
    FINGERPRINT_SPI_INIT       = 1,
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
    FINGERPRINT_DEV2_RESET_FLASH,
    FINGERPRINT_DEV2_SET_CLK_PIN_VALUE,
    FINGERPRINT_PC_PIN_INIT = 20,
};

struct fp_cmd_info {
    u8 command;
    union{
        u8 module_value;
        u8 fp_spi_cs;
    };
    union{
        u8 irq_pin_value;
        u8 fp_irq_pin;
    };
    u8 reset_pin_value;
    union{
        u8 product_value;
        u8 fp_spi_num;
    };
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
    uint64_t sh_img_buf;
#else
    uint32_t sh_img_buf; // the image get from sensorhub
#endif
    u32 sh_img_size;
    int32_t sh_fail_img_cnt;
    int32_t sh_anti_touch_cnt;
    uint32_t sh_shared_mem_addr_offset;
    u8 reset_pin_direction;
    u8 irq_pin_pull_type;
    u8 clk_pin_value;
};

struct spi_transaction_info {
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
    uint64_t reg_addr;
    uint64_t buf_addr;
#else
    uint32_t reg_addr;
    uint32_t buf_addr;
#endif
    unsigned int reg_len;
    unsigned int buf_len;
};

int driver_fingerprint_command(struct fp_cmd_info *command_info);
int driver_spi_full_duplex(struct spi_transaction_info *write_info, struct spi_transaction_info *read_info);
int driver_spi_full_duplex_with_speed(
    struct spi_transaction_info *write_info, struct spi_transaction_info *read_info, int speed);
int driver_spi_half_duplex_with_speed(
    struct spi_transaction_info *write_info, struct spi_transaction_info *read_info, int speed);
int driver_read_image_from_sensorhub(uint8_t *img_buf, uint32_t img_size, uint32_t addr_offset, uint8_t img_type);
int spi_tui_mutex(void);

#endif

