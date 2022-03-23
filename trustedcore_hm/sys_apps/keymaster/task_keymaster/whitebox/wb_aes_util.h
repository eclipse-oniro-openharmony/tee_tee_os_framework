/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: wb_aes_util
 * Create: 2012-01-17
 */

#ifndef __WB_AES_UTIL_H
#define __WB_AES_UTIL_H
#include <stdint.h>
#define table(tb, r, col, row, i)      (tb)[(r) << (s + 4) | (col) << (s + 2) | (row) << s | (i)]
/*
 * 64-bit integer manipulation macros (little endian)
 */
#define get_uint64_le(n, b, i) do { \
    (n) = ((uint64_t)(b)[(i)]) \
        | ((uint64_t)(b)[(i) + 1] << 16) \
        | ((uint64_t)(b)[(i) + 2] << 32) \
        | ((uint64_t)(b)[(i) + 3] << 48); \
} while (0)

#define put_uint64_le(n, b, i) do { \
    (b)[(i)] = (uint16_t) ((n)); \
    (b)[(i) + 1] = (uint16_t)((n) >> 16); \
    (b)[(i) + 2] = (uint16_t)((n) >> 32); \
    (b)[(i) + 3] = (uint16_t)((n) >> 48); \
} while (0)

/*
 * 32-bit integer manipulation macros (little endian)
 */
#define get_uint32_le(n, b, i) do { \
    (n) = ((uint32_t)((b)[(i)] & 0xff)) \
        | ((uint32_t)((b)[(i) + 1] & 0xff) <<  8) \
        | ((uint32_t)((b)[(i) + 2] & 0xff) << 16) \
        | ((uint32_t)((b)[(i) + 3] & 0xff) << 24); \
} while (0)

#define put_uint32_le(n, b, i) do { \
    (b)[(i)] = (uint8_t) ((n)); \
    (b)[(i) + 1] = (uint8_t) ((n) >> 8); \
    (b)[(i) + 2] = (uint8_t) ((n) >> 16); \
    (b)[(i) + 3] = (uint8_t) ((n) >> 24);  \
} while (0)


uint16_t rotl(uint16_t x, int n, int m);
void xor_block(uint8_t *tar, const uint8_t *src, uint32_t len);

#endif /* WB_AES_UTIL_H_ */
