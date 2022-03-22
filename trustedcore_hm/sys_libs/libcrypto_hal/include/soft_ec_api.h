/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
* Description: implament GP API using boringssl
* Create: 2020-06-02
*/
#ifndef _SOFT_EC_API_H
#define _SOFT_EC_API_H

#include <crypto_driver_adaptor.h>

int32_t soft_crypto_ecc_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key);

int32_t soft_crypto_ecc_encrypt(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *data_in,
    struct memref_t *data_out);

int32_t soft_crypto_ecc_decrypt(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *data_in,
    struct memref_t *data_out);

int32_t soft_crypto_ecc_sign_digest(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest,
    struct memref_t *signature);

int32_t soft_crypto_ecc_verify_digest(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest,
    const struct memref_t *signature);
#endif
