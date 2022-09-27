/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:lBRwzWIfWflpkuvEPG9oHU2mxP0IzvCfvv+i+/xvfe6PT8VRR+8jz7b5YQbqzI49/C6xSBgi
2fFxGZUs+G3nkUIkBkfRerjPcgJTCLqrXspNkFCGTLklL/GZHRhiXBwGnNKhh0MAXEOVfrQU
iukZUWJ4vidruSf/U7e9gpUyQAooCWCSaeb3aIYEst5WD1qne8GcO+5QGB0g7/S8T09ixUGT
nR+osDAHaIEfyoPHfIFAJAQLD0ohh2OwUozrcXB/#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: implementation of get_valid_bit in tee bitmap
 * Author: Zhangzhangkai z00497210
 * Create: 2019-01-31
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
