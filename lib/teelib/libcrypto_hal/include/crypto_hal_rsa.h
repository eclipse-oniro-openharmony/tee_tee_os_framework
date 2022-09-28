/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: RSA Crypto API at driver adaptor.
 * Create: 2020-12-22
 */

#ifndef CRYPTO_HAL_RSA_H_
#define CRYPTO_HAL_RSA_H_

#include <crypto_driver_adaptor.h>

int32_t tee_crypto_rsa_generate_keypair(uint32_t key_size, const struct memref_t *e_value, bool crt_mode,
    struct rsa_priv_key_t *key_pair, uint32_t engine);
int32_t tee_crypto_rsa_encrypt(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t engine);
int32_t tee_crypto_rsa_decrypt(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t engine);
int32_t tee_crypto_rsa_sign_digest(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *digest,
    struct memref_t *signature, uint32_t engine);
int32_t tee_crypto_rsa_verify_digest(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *digest,
    const struct memref_t *signature, uint32_t engine);

#endif
