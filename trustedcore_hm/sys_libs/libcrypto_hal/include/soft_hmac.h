/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: soft crypto implementation
 * Create: 2020-10-27
 */
#ifndef _SOFT_HMAC_H
#define _SOFT_HMAC_H

#include <crypto_syscall.h>
#include <crypto_driver_adaptor.h>

int32_t soft_crypto_hmac_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key);

int32_t soft_crypto_hmac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in);

int32_t soft_crypto_hmac_dofinal(struct ctx_handle_t *ctx, struct memref_t *data_out);

int32_t soft_crypto_hmac(uint32_t alg_type, const struct symmerit_key_t *key, const struct memref_t *data_in,
    struct memref_t *data_out);

#endif
