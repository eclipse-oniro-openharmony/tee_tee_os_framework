/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: hsm efuse ta head file
 * Author: huawei
 * Create: 2020-07-10
 */
#ifndef EFUSE_TA_API_H
#define EFUSE_TA_API_H

#include <stdint.h>

#define EFUSE_CTX_MAX_SIZE 512

#ifdef STATIC_SKIP
#define STATIC
#else
#define STATIC static
#endif

void efuse_set_dev_id(uint32_t dev_id);

uint32_t sec_efuse_write(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
    uint8_t *efuse_ctx, uint32_t efuse_len, uint32_t dev_id);

uint32_t sec_efuse_burn(uint32_t efuse_block_num, uint32_t dev_id);

uint32_t sec_efuse_check(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
    uint8_t *efuse_ctx, uint32_t efuse_len, uint32_t dev_id);

#endif
