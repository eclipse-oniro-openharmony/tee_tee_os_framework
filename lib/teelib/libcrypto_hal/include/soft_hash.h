/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: soft crypto implementation
 * Create: 2020-10-27
 */
#ifndef _SOFT_HASH_H
#define _SOFT_HASH_H

#include <crypto_driver_adaptor.h>

int32_t soft_crypto_hash_init(struct ctx_handle_t *ctx);

int32_t soft_crypto_hash_update(struct ctx_handle_t *ctx, const struct memref_t *data_in);

int32_t soft_crypto_hash_dofinal(struct ctx_handle_t *ctx, struct memref_t *data_out);

int32_t soft_crypto_hash(uint32_t alg_type, const struct memref_t *data_in, struct memref_t *data_out);

#endif
