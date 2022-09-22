/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: AE Crypto API at driver adaptor.
 * Create: 2020-12-22
 */
#ifndef CRYPTO_HAL_AE_H
#define CRYPTO_HAL_AE_H

#include <crypto_driver_adaptor.h>

struct ctx_handle_t *tee_crypto_ae_init(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param, uint32_t engine);
int32_t tee_crypto_ae_update_aad(struct ctx_handle_t *ctx, const struct memref_t *aad_data);
int32_t tee_crypto_ae_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out);
int32_t tee_crypto_ae_enc_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out, struct memref_t *tag_out);
int32_t tee_crypto_ae_dec_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag_in, struct memref_t *data_out);

#endif
