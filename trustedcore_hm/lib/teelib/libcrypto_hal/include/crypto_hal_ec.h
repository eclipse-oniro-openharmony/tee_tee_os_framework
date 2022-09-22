/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: EC Crypto API at driver adaptor.
 * Create: 2020-12-22
 */

#ifndef CRYPTO_HAL_EC_H_
#define CRYPTO_HAL_EC_H_

#include <crypto_driver_adaptor.h>

int32_t tee_crypto_ecc_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key, uint32_t engine);
int32_t tee_crypto_ecc_encrypt(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t engine);
int32_t tee_crypto_ecc_decrypt(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t engine);
int32_t tee_crypto_ecc_sign_digest(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest,
    struct memref_t *signature, uint32_t engine);
int32_t tee_crypto_ecc_verify_digest(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest,
    const struct memref_t *signature, uint32_t engine);

#endif
