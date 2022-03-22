/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: efuse libs source file
* Author: chenyao
* Create: 2020/4/27
*/
#include "tee_bit_ops.h"
#include "sre_syscall.h"
#include "sre_syscalls_id_ext.h"

#include "hmdrv.h"

#include "syscall_api_common.h"
#include "efuse_lib_api.h"

uint32_t lib_efuse_write(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
    uint8_t *efuse_ctx, uint32_t efuse_len, uint32_t dev_id)
{
    uint64_t input_addr = (uint64_t)(uintptr_t)efuse_ctx;
    uint64_t args[] = {
        efuse_block_num,
        start_bit,
        dest_size,
        (uint64_t)HIGH_32BIT(input_addr), (uint64_t)LOW_32BIT(input_addr),
        efuse_len,
        dev_id,
    };

    return hm_drv_call(SYSCALL_HSM_EFUSE_WRITE, args, ARRAY_SIZE(args));
}

uint32_t lib_efuse_burn(uint32_t efuse_block_num, uint32_t dev_id)
{
    uint64_t args[] = {
        efuse_block_num,
        dev_id,
    };

    return hm_drv_call(SYSCALL_HSM_EFUSE_BURN, args, ARRAY_SIZE(args));
}

uint32_t lib_efuse_check(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
    uint8_t *efuse_ctx, uint32_t efuse_len, uint32_t dev_id)
{
    uint64_t input_addr = (uint64_t)(uintptr_t)efuse_ctx;

    uint64_t args[] = {
        efuse_block_num,
        start_bit,
        dest_size,
        (uint64_t)HIGH_32BIT(input_addr), (uint64_t)LOW_32BIT(input_addr),
        efuse_len,
        dev_id,
    };

    return hm_drv_call(SYSCALL_HSM_EFUSE_CHECK, args, ARRAY_SIZE(args));
}
uint32_t lib_efuse_nv_cnt_burn(uint32_t nv_cnt, uint32_t dev_id)
{
    uint64_t args[] = {
        nv_cnt,
        dev_id,
    };

    return hm_drv_call(SYSCALL_HSM_EFUSE_NV_CNT_BURN, args, ARRAY_SIZE(args));
}

uint32_t lib_efuse_nv_cnt_check(uint32_t nv_cnt, uint32_t dev_id)
{
    uint64_t args[] = {
        nv_cnt,
        dev_id,
    };

    return hm_drv_call(SYSCALL_HSM_EFUSE_NV_CNT_CHECK, args, ARRAY_SIZE(args));
}

uint32_t lib_efuse_boot_check(uint32_t dev_id)
{
    uint64_t args[] = {
        dev_id,
    };

    return hm_drv_call(SYSCALL_HSM_EFUSE_NS_FORIBID_CHECK, args, ARRAY_SIZE(args));
}
