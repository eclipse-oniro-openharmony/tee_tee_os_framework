/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: efuse libs api file
* Author: huawei
* Create: 2020/4/27
*/

#ifndef EFUSE_LIB_API_H
#define EFUSE_LIB_API_H

#include <stdint.h>

uint32_t lib_efuse_write(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
    uint8_t *efuse_ctx, uint32_t efuse_len, uint32_t dev_id);

uint32_t lib_efuse_burn(uint32_t efuse_block_num, uint32_t dev_id);

uint32_t lib_efuse_check(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
    uint8_t *efuse_ctx, uint32_t efuse_len, uint32_t dev_id);

uint32_t lib_efuse_nv_cnt_burn(uint32_t nv_cnt, uint32_t dev_id);

uint32_t lib_efuse_nv_cnt_check(uint32_t nv_cnt, uint32_t dev_id);

uint32_t lib_efuse_boot_check(uint32_t dev_id);

#endif
