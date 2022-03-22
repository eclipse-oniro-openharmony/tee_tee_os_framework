/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
* Description: sfc libs source file
* Author: chenyao
* Create: 2019/11/2
*/
#include "sre_syscalls_id_ext.h"
#include "hmdrv.h"

#include "syscall_api_common.h"
#include "sfc_lib_api.h"

uint32_t lib_mdc_flash_read(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX4] = {0};

    args[ARRAY_INDEX0] = offset;
    args[ARRAY_INDEX1] = length;
    args[ARRAY_INDEX2] = chip_id;
    args[ARRAY_INDEX3] = (uint64_t)(uintptr_t)(buffer);

    return hm_drv_call(SYSCALL_MDC_FLASH_READ, args, ARRAY_SIZE(args));
}

uint32_t lib_mdc_flash_write(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX4] = {0};

    args[ARRAY_INDEX0] = offset;
    args[ARRAY_INDEX1] = length;
    args[ARRAY_INDEX2] = chip_id;
    args[ARRAY_INDEX3] = (uint64_t)(uintptr_t)(buffer);

    return hm_drv_call(SYSCALL_MDC_FLASH_WRITE, args, ARRAY_SIZE(args));
}

uint32_t lib_mdc_flash_erase(uint32_t offset, uint32_t length, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX4] = {0};

    args[ARRAY_INDEX0] = offset;
    args[ARRAY_INDEX1] = length;
    args[ARRAY_INDEX2] = chip_id;

    return hm_drv_call(SYSCALL_MDC_FLASH_ERASE, args, ARRAY_SIZE(args));
}
