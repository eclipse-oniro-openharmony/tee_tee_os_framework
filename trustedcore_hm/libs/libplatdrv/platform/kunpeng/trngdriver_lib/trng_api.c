/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: trng driver syscall
 * Author: wangcong48@huawei.com
 * Create: 2020-03
 */

#include "trng_api.h"
#include <tee_log.h>

uint32_t read_rng_value(uint32_t offset)
{
    uint32_t tmp_value = 0;
    if (offset > MAX_OFFSET) {
        tloge("offset error %u\n", offset);
        return tmp_value;
    }

    do
        tmp_value = trng_read32(TRNG_BASE_ADDR_CHIP0 + 0xf0 + offset * WORD_SIZE);
    while (tmp_value == 0);

    return tmp_value;
}

#define TRNG_OFFSET_RNG_NUM (0xD8)
uint32_t read_entropy_value(uint32_t offset)
{
    uint32_t tmp_value = 0;
    if (offset > MAX_OFFSET)
        return tmp_value;

    do
        tmp_value = trng_read32(TRNG_BASE_ADDR_CHIP0 + TRNG_OFFSET_RNG_NUM + offset * WORD_SIZE);
    while (tmp_value == 0);

    return tmp_value;
}
