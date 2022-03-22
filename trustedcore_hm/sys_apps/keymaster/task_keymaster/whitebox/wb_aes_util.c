/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: aes util
 * Create: 2012-01-17
 */
#include "wb_aes_util.h"

#ifndef NULL
#define NULL 0
#endif

uint16_t rotl(uint16_t x, int n, int m)
{
    if (m == 0)
        return 0;
    uint16_t mask = (1 << (unsigned int)m) - 1;
    unsigned int rot = (unsigned int)(n % m);
    uint16_t ret = (x << rot) | (x >> ((unsigned int)m - rot));
    return ret & mask;
}

void xor_block(uint8_t *tar, const uint8_t *src, uint32_t len)
{
    if (tar == NULL || src == NULL)
        return;
    uint32_t i;
    for (i = 0; i < len; ++i)
        tar[i] ^= src[i];
}
