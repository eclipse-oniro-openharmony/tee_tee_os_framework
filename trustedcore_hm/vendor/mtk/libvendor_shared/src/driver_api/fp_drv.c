/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Author: h00424236
 * Create: 2019-05-08
 * Description: fingerprint driver interface.
 */
#include <stdint.h>
#include <stdlib.h>
#include <hm_mman_ext.h>
#include "lib_timer.h"
#include "sre_hwi.h"
#include "sre_task.h"
#include "sre_syscall.h"
#include "sre_syscalls_ext.h"
#include "tee_internal_api.h"
#include "tee_log.h"

#include <sre_syscalls_id.h>
#include <sre_syscalls_id_ext.h>

#include "hmdrv.h"

#define FP_RET_SUCCESS                      0
#define FP_RET_FAIL                         (-1)

struct fp_cmd_info {
    unsigned char command;
    unsigned char module_value;
    unsigned char irq_pin_value;
    unsigned char reset_pin_value;
    unsigned char product_value;
    unsigned char *sensorhub_img_buf;
    unsigned int sensorhub_img_size;
    int32_t sensorhub_fail_img_cnt;
    int32_t sensorhub_anti_touch_cnt;
    int32_t max_score;
    unsigned char reset_pin_direction;
    unsigned char irq_pin_pull_type;
};

struct fp_cmd_info_64 {
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
    unsigned char *reg_addr;
    unsigned char *buf_addr;
    unsigned int reg_len;
    unsigned int buf_len;
};

struct spi_transaction_info_64 {
    uint64_t reg_addr;
    uint64_t buf_addr;
    unsigned int reg_len;
    unsigned int buf_len;
};

int __driver_fingerprint_command(void *command_info)
{
    if (command_info == NULL) {
        tloge("command_info pointer is NULL");
        return FP_RET_FAIL;
    }

    int ret;
    struct fp_cmd_info_64 command_info_64 = {0};
    struct fp_cmd_info_64 *ptr_command_info_64 = &command_info_64;
    ptr_command_info_64->command = ((struct fp_cmd_info *)command_info)->command;
    ptr_command_info_64->module_value =
        ((struct fp_cmd_info *)command_info)->module_value;
    ptr_command_info_64->irq_pin_value =
        ((struct fp_cmd_info *)command_info)->irq_pin_value;
    ptr_command_info_64->reset_pin_value =
        ((struct fp_cmd_info *)command_info)->reset_pin_value;
    ptr_command_info_64->product_value =
        ((struct fp_cmd_info *)command_info)->product_value;
    ptr_command_info_64->sensorhub_img_buf =
       (uint64_t)(((struct fp_cmd_info *)command_info)->sensorhub_img_buf);
    ptr_command_info_64->sensorhub_img_size =
        ((struct fp_cmd_info *)command_info)->sensorhub_img_size;
    ptr_command_info_64->sensorhub_fail_img_cnt =
        ((struct fp_cmd_info *)command_info)->sensorhub_fail_img_cnt;
    ptr_command_info_64->sensorhub_anti_touch_cnt =
        ((struct fp_cmd_info *)command_info)->sensorhub_anti_touch_cnt;
    ptr_command_info_64->max_score =
        ((struct fp_cmd_info *)command_info)->max_score;
    ptr_command_info_64->reset_pin_direction =
        ((struct fp_cmd_info *)command_info)->reset_pin_direction;
    ptr_command_info_64->irq_pin_pull_type =
        ((struct fp_cmd_info *)command_info)->irq_pin_pull_type;

    uint64_t args[] = {
        (uint64_t)(uintptr_t)ptr_command_info_64,
    };

    ret = hm_drv_call(SW_SYSCALL_FP_COMMAND_INFO, args, ARRAY_SIZE(args));
    ((struct fp_cmd_info *)command_info)->product_value = ptr_command_info_64->product_value;
    ((struct fp_cmd_info *)command_info)->sensorhub_img_buf = (uint8_t *)(ptr_command_info_64->sensorhub_img_buf);
    return ret;
}

static void change_to_64(void *spi_info, struct spi_transaction_info_64 **p_spi_info,
                         struct spi_transaction_info_64 *spi_trans_info)
{
    if (((struct spi_transaction_info *)spi_info)->reg_addr != NULL)
        spi_trans_info->reg_addr =
            (uint64_t)(((struct spi_transaction_info *)spi_info)->reg_addr);

    if (((struct spi_transaction_info *)spi_info)->buf_addr != NULL)
        spi_trans_info->buf_addr =
            (uint64_t)(((struct spi_transaction_info *)spi_info)->buf_addr);

    spi_trans_info->reg_len = ((struct spi_transaction_info *)spi_info)->reg_len;
    spi_trans_info->buf_len = ((struct spi_transaction_info *)spi_info)->buf_len;
    *p_spi_info = spi_trans_info;
}

int __driver_spi_full_duplex(void *p_write_info, void *p_read_info)
{
    if (p_write_info == NULL && p_read_info == NULL) {
        tloge("p_write_info and p_read_info pointer is NULL");
        return FP_RET_FAIL;
    }

    struct spi_transaction_info_64 s_write_info_64 = {0};
    struct spi_transaction_info_64 s_read_info_64 = {0};
    struct spi_transaction_info_64 *p_write_info_64 = NULL;
    struct spi_transaction_info_64 *p_read_info_64 = NULL;

    if (p_write_info != NULL)
        change_to_64(p_write_info, &p_write_info_64, &s_write_info_64);
    if (p_read_info != NULL)
        change_to_64(p_read_info, &p_read_info_64, &s_read_info_64);

    uint64_t args[] = {
        (uint64_t)(uintptr_t)p_write_info_64,
        (uint64_t)(uintptr_t)p_read_info_64,
    };

    return hm_drv_call(SW_SYSCALL_FP_SPI_TRANSACTION, args, ARRAY_SIZE(args));
}

int __driver_spi_full_duplex_with_speed(void *p_write_info, void *p_read_info, int speed)
{
    if (p_write_info == NULL && p_read_info == NULL) {
        tloge("p_write_info and p_read_info is NULL");
        return FP_RET_FAIL;
    }

    struct spi_transaction_info_64 s_write_info_64 = {0};
    struct spi_transaction_info_64 s_read_info_64 = {0};
    struct spi_transaction_info_64 *p_write_info_64 = NULL;
    struct spi_transaction_info_64 *p_read_info_64 = NULL;

    if (p_write_info != NULL)
        change_to_64(p_write_info, &p_write_info_64, &s_write_info_64);
    if (p_read_info != NULL)
        change_to_64(p_read_info, &p_read_info_64, &s_read_info_64);

    uint64_t args[] = {
        (uint64_t)(uintptr_t)p_write_info_64,
        (uint64_t)(uintptr_t)p_read_info_64,
        (uint64_t)speed,
    };

    return hm_drv_call(SW_SYSCALL_FP_SPI_FULL_DUPLEX_WITH_SPEED_TRANSACTION, args,
                       ARRAY_SIZE(args));
}

int __driver_spi_half_duplex_with_speed(void *p_write_info, void *p_read_info, int speed)
{
    return __driver_spi_full_duplex_with_speed(p_write_info, p_read_info, speed);
}

int __driver_spi_dev2_full_duplex(void *p_write_info, void *p_read_info)
{
    return __driver_spi_full_duplex(p_write_info, p_read_info);
}

int __driver_spi_dev2_full_duplex_with_speed(void *p_write_info, void *p_read_info, int speed)
{
    return __driver_spi_full_duplex_with_speed(p_write_info, p_read_info, speed);
}

int __driver_spi_dev2_half_duplex_with_speed(void *p_write_info, void *p_read_info, int speed)
{
    return __driver_spi_full_duplex_with_speed(p_write_info, p_read_info, speed);
}
