/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: implementation of get_valid_bit in tee bitmap
 * Create: 2020-12-02
 */

#include "tee_bitmap.h"

#define INVALID_BIT (-1)

int32_t get_valid_bit(const uint8_t *bitmap, uint32_t bit_max)
{
    uint32_t index1;
    uint32_t index2;
    int32_t  valid_bit = INVALID_BIT;

    if (bitmap == NULL)
        return valid_bit;

    for (index1 = 0; index1 < (bit_max >> MOVE_BIT); index1++) {
        if (bitmap[index1] == BITMAP_MASK)
            continue;
        for (index2 = 0; index2 < INDEX_MAX; index2++) {
            if (!(bitmap[index1] & (0x1U << index2))) {
                valid_bit = index1 * INDEX_MAX + index2;
                break;
            }
        }
        if (valid_bit != INVALID_BIT)
            break;
    }

    return valid_bit;
}
