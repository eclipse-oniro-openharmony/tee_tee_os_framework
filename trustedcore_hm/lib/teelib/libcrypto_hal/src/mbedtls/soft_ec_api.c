/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: implement GP API using mbedtls
 * Create: 2020-11-27
 */
#include "soft_ec_api.h"
#include <crypto_driver_adaptor.h>

int32_t soft_crypto_ecc_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key)
{
    (void)key_size;
    (void)curve;
    (void)public_key;
    (void)private_key;

    return CRYPTO_NOT_SUPPORTED;
}

int32_t soft_crypto_ecc_encrypt(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)alg_type;
    (void)ec_params;
    (void)public_key;
    (void)data_in;
    (void)data_out;

    return CRYPTO_NOT_SUPPORTED;
}

int32_t soft_crypto_ecc_decrypt(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)alg_type;
    (void)ec_params;
    (void)private_key;
    (void)data_in;
    (void)data_out;

    return CRYPTO_NOT_SUPPORTED;
}

int32_t soft_crypto_ecc_sign_digest(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest,
    struct memref_t *signature)
{
    (void)alg_type;
    (void)ec_params;
    (void)private_key;
    (void)digest;
    (void)signature;

    return CRYPTO_NOT_SUPPORTED;
}

int32_t soft_crypto_ecc_verify_digest(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest,
    const struct memref_t *signature)
{
    (void)alg_type;
    (void)ec_params;
    (void)public_key;
    (void)digest;
    (void)signature;

    return CRYPTO_NOT_SUPPORTED;
}
