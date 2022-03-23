/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: manage tee bitmap
 * Create: 2020-12-02
 */
#ifndef LIBTEEOS_TEE_BITMAP_H
#define LIBTEEOS_TEE_BITMAP_H

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#define MOVE_BIT    3
#define INDEX_MAX   8
#define BITMAP_MASK 0xFF

int32_t get_valid_bit(const uint8_t *bitmap, uint32_t bit_max);

static inline bool is_bit_seted(const uint8_t *bitmap, uint32_t bit_max, uint32_t bit)
{
    if ((bitmap == NULL) || (bit >= bit_max))
        return false;

    return (((bitmap[bit >> MOVE_BIT]) & (0x1 << (bit % INDEX_MAX))) ? true : false);
}

static inline void set_bitmap(uint8_t *bitmap, uint32_t bit_max, uint32_t bit)
{
    if ((bitmap == NULL) || (bit >= bit_max))
        return;

    bitmap[bit >> MOVE_BIT] = (bitmap[bit >> MOVE_BIT]) | (0x1 << (bit % INDEX_MAX));
}

static inline void clear_bitmap(uint8_t *bitmap, uint32_t bit_max, uint32_t bit)
{
    if ((bitmap == NULL) || (bit >= bit_max))
        return;

    bitmap[bit >> MOVE_BIT] = (bitmap[bit >> MOVE_BIT]) & (~(uint8_t)(0x1 << (bit % INDEX_MAX)));
}
#endif
