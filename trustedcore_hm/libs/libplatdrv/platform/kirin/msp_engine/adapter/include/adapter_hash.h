/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: adapter hash api
 * Author: s00294296
 * Create: 2020-03-31
 */
#ifndef __ADAPTER_HASH_H__
#define __ADAPTER_HASH_H__

#include <adapter_common.h>

int adapter_hash_init(void *ctx, uint32_t alg_type);

int adapter_hash_update(void *ctx, const struct memref_t *data_in);

int adapter_hash_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out);

int adapter_hash_single(uint32_t alg_type, const struct memref_t *data_in, struct memref_t *data_out);

#endif

