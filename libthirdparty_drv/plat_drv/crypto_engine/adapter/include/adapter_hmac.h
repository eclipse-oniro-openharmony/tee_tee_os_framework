/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: adapter hmac api
 * Author: s00294296
 * Create: 2020-03-31
 */
#ifndef __ADAPTER_HMAC_H__
#define __ADAPTER_HMAC_H__

#include <adapter_common.h>

int adapter_hmac_init(uint32_t alg_type, void *ctx, const struct symmerit_key_t *key);

int adapter_hmac_update(void *ctx, const struct memref_t *data_in);

int adapter_hmac_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out);

int adapter_hmac_single(uint32_t alg_type, const struct symmerit_key_t *key,
			const struct memref_t *data_in, struct memref_t *data_out);

#endif

