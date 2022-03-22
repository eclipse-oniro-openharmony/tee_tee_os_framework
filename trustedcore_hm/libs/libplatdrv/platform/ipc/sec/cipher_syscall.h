/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: trng driver syscall
 * Author: liujunliujunliujun.liu@huawei.com
 * Create: 2020-07
 */
#ifndef PLATDRV_TRNG_API_H
#define PLATDRV_TRNG_API_H

#include <stdint.h>
#include <stddef.h>

#define CIPHER_KEY_SIZE_IN_BYTE 16
#define CIPHER_KEY_SIZE_IN_WORD (CIPHER_KEY_SIZE_IN_BYTE / 4)
int32_t trng_get_random(uint8_t *trng_addr, uint32_t length);
int32_t cipher_derivekey(const uint8_t *pdata_in, size_t data_size, uint32_t key[CIPHER_KEY_SIZE_IN_WORD]);
#endif
