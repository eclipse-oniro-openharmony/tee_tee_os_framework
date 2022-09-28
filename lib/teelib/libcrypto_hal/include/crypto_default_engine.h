/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Crypto API at driver adaptor.
 * Create: 2020-04-10
 */
#ifndef CRYPTO_DEFAULT_ENGINE_H
#define CRYPTO_DEFAULT_ENGINE_H

#include <crypto_driver_adaptor.h>

#define DX_CRYPTO   0
#define EPS_CRYPTO  1
#define SOFT_CRYPTO 2
#define SEC_CRYPTO  3

struct algorithm_engine_t {
    uint32_t             algorithm;
    uint32_t             engine;
};

const struct algorithm_engine_t g_algorithm_engine[] = {
    { 0,       SOFT_CRYPTO },
};
const struct algorithm_engine_t g_generate_key_engine[] = {
    { 0,       SOFT_CRYPTO },
};

#endif
