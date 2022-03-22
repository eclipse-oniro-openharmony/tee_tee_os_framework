/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: implement GP API using mbedtls
 * Create: 2020-11-27
 */
#include "soft_derive_key_api.h"
#include <crypto_driver_adaptor.h>

int32_t soft_crypto_ecdh_derive_key(uint32_t alg_type, const struct ecc_pub_key_t *client_key,
    const struct ecc_priv_key_t *server_key, const struct asymmetric_params_t *ec_params,
    struct memref_t *secret)
{
    (void)alg_type;
    (void)ec_params;
    (void)client_key;
    (void)server_key;
    (void)secret;

    return CRYPTO_NOT_SUPPORTED;
}

int32_t soft_crypto_pbkdf2(const struct memref_t *password, const struct memref_t *salt,
    uint32_t iterations, uint32_t digest_type, struct memref_t *data_out)
{
    (void)iterations;
    (void)digest_type;
    (void)password;
    (void)salt;
    (void)data_out;

    return CRYPTO_NOT_SUPPORTED;
}
