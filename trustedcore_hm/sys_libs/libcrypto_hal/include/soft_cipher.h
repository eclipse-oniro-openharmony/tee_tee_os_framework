/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: soft crypto implementation
 * Create: 2020-10-27
 */
#ifndef _SOFT_CIPHER_H
#define _SOFT_CIPHER_H

#include <crypto_syscall.h>
#include <crypto_driver_adaptor.h>

int32_t soft_crypto_cipher_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key, const struct memref_t *iv);

int32_t soft_crypto_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out);

int32_t soft_crypto_cipher_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out);

int32_t soft_crypto_cipher(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
    const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out);

#endif
