/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: implament GP API using boringssl
 * Create: 2020-06-02
 */
#ifndef _SOFT_AE_H
#define _SOFT_AE_H

#include <crypto_driver_adaptor.h>

int32_t soft_crypto_ae_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param);

int32_t soft_crypto_ae_update_aad(struct ctx_handle_t *ctx, const struct memref_t *aad_data);

int32_t soft_crypto_ae_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out);

int32_t soft_crypto_ae_enc_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out, struct memref_t *tag_out);

int32_t soft_crypto_ae_dec_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag_in, struct memref_t *data_out);

#endif
