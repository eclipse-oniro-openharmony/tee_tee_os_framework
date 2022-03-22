/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Hash Crypto API at driver adaptor.
 * Create: 2020-12-22
 */

#ifndef CRYPTO_HAL_HASH_H
#define CRYPTO_HAL_HASH_H

#include <crypto_driver_adaptor.h>
#include <crypto_syscall.h>

struct ctx_handle_t *tee_crypto_hash_init(uint32_t alg_type, uint32_t engine);
int32_t tee_crypto_hash_update(struct ctx_handle_t *ctx, const struct memref_t *data_in);
int32_t tee_crypto_hash_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out);
int32_t tee_crypto_hash(uint32_t alg_type, const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine);

#endif
