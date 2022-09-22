/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: HMAC Crypto API at driver adaptor.
 * Create: 2020-12-22
 */
#ifndef CRYPTO_HAL_HMAC_H
#define CRYPTO_HAL_HMAC_H

#include <crypto_driver_adaptor.h>

struct ctx_handle_t *tee_crypto_hmac_init(uint32_t alg_type, const struct symmerit_key_t *key, uint32_t engine);
int32_t tee_crypto_hmac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in);
int32_t tee_crypto_hmac_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out);
int32_t tee_crypto_hmac(uint32_t alg_type, const struct symmerit_key_t *key,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine);

#endif
