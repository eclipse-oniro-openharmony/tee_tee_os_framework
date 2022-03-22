/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: adapter symm crypto api
 * Author: s00294296
 * Create: 2020-03-31
 */
#ifndef __ADAPTER_CIPHER_H__
#define __ADAPTER_CIPHER_H__

#include <adapter_common.h>

int adapter_cipher_init(uint32_t alg_type, void *ctx, uint32_t direction,
			const struct symmerit_key_t *key, const struct memref_t *iv);

int adapter_cipher_update(void *ctx, const struct memref_t *data_in, struct memref_t *data_out);

int adapter_cipher_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out);

int adapter_cipher_single(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
			  const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out);
#endif

