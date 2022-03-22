/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Create: 2019-05-08
 * Description: fingerprint driver interface.
 */

#include <stdint.h>
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

int __driver_fingerprint_command(void *command_info)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)command_info,
    };

    return hm_drv_call(SW_SYSCALL_FP_COMMAND_INFO, args, ARRAY_SIZE(args));
}

int __driver_spi_full_duplex(void *p_write_info, void *p_read_info)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)p_write_info,
        (uint64_t)(uintptr_t)p_read_info,
    };

    return hm_drv_call(SW_SYSCALL_FP_SPI_TRANSACTION, args, ARRAY_SIZE(args));
}

int __driver_spi_full_duplex_with_speed(void *p_write_info, void *p_read_info, int speed)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)p_write_info,
        (uint64_t)(uintptr_t)p_read_info,
        (uint64_t)speed,
    };

    return hm_drv_call(SW_SYSCALL_FP_SPI_FULL_DUPLEX_WITH_SPEED_TRANSACTION, args, ARRAY_SIZE(args));
}

int __driver_spi_half_duplex_with_speed(void *p_write_info, void *p_read_info, int speed)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)p_write_info,
        (uint64_t)(uintptr_t)p_read_info,
        (uint64_t)speed,
    };

    return hm_drv_call(SW_SYSCALL_FP_SPI_HALF_DUPLEX_WITH_SPEED_TRANSACTION, args, ARRAY_SIZE(args));
}

int __driver_spi_dev2_full_duplex(void *p_write_info, void *p_read_info)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)p_write_info,
        (uint64_t)(uintptr_t)p_read_info,
    };

    return hm_drv_call(SW_SYSCALL_FP_SPI_DEV2_TRANSACTION, args, ARRAY_SIZE(args));
}

int __driver_spi_dev2_full_duplex_with_speed(void *p_write_info, void *p_read_info, int speed)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)p_write_info,
        (uint64_t)(uintptr_t)p_read_info,
        (uint64_t)speed,
    };

    return hm_drv_call(SW_SYSCALL_FP_SPI_DEV2_FULL_DUPLEX_WITH_SPEED_TRANSACTION, args, ARRAY_SIZE(args));
}

int __driver_spi_dev2_half_duplex_with_speed(void *p_write_info, void *p_read_info, int speed)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)p_write_info,
        (uint64_t)(uintptr_t)p_read_info,
        (uint64_t)speed,
    };

    return hm_drv_call(SW_SYSCALL_FP_SPI_DEV2_HALF_DUPLEX_WITH_SPEED_TRANSACTION, args, ARRAY_SIZE(args));
}

int __driver_fp_set_spi_mode(int mode)
{
    uint64_t args[] = {
        (uint64_t)mode,
    };

    return hm_drv_call(SW_SYSCALL_FP_SET_SPI_MODE, args, ARRAY_SIZE(args));
}

