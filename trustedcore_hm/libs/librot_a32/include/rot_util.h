/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: util function of ROT Service.
 * Author: t00360454
 * Create: 2020-03-23
 * History: 2020-03-23 t00360454 create.
 */
#ifndef _ROOT_OF_TRUST_UTIL_H_
#define _ROOT_OF_TRUST_UTIL_H_
#include <tee_internal_api.h>

/* get minimum value */
#define min(a, b) (((a) > (b)) ? (b) : (a))

/* array operations with big-endian */
#define get_u16(array, offset) ((uint16_t)((((array)[(offset)]) << 8) | ((array)[(offset) + 1])))

#define set_u16(array, offset, value)           \
    do {                                        \
        (array)[offset] = ((value) >> 8) & 0xFF;\
        (array)[(offset) + 1] = (value) & 0xFF; \
    } while (0)

#define set_u32(array, offset, value)                   \
    do {                                                \
        (array)[offset] = ((value) >> 24) & 0xFF;       \
        (array)[(offset) + 1] = ((value) >> 16) & 0xFF; \
        (array)[(offset) + 2] = ((value) >> 8) & 0xFF;  \
        (array)[(offset) + 3] = (value) & 0xFF;         \
    } while (0)

#endif
