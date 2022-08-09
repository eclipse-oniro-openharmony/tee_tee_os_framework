/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Cipher Crypto API at driver adaptor.
 * Create: 2020-12-22
 */
#ifndef CRYPTO_HAL_CIPHER_H
#define CRYPTO_HAL_CIPHER_H

#include <crypto_driver_adaptor.h>

struct ctx_handle_t *tee_crypto_cipher_init(uint32_t alg_type, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv, uint32_t engine);
int32_t tee_crypto_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out);
int32_t tee_crypto_cipher_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out);
int32_t tee_crypto_cipher(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
    const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine);

#endif
