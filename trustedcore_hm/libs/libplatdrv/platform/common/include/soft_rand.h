/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: soft rand defines
 * Create: 2020-11-25
 */
#ifndef SOFT_RAND_H_
#define SOFT_RAND_H_
#include <stdint.h>
#include <crypto_driver_adaptor.h>

int32_t get_rands(uint32_t length, uint8_t *random_addr);
int32_t soft_crypto_init(void);
const struct crypto_ops_t *get_soft_ops(void);
#endif
