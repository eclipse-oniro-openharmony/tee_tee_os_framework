/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
* Description: implament GP API using boringssl
* Create: 2020-06-02
*/
#ifndef _SOFT_DERIVE_KEY_API_H
#define _SOFT_DERIVE_KEY_API_H

#include <crypto_driver_adaptor.h>

int32_t soft_crypto_ecdh_derive_key(uint32_t alg_type, const struct ecc_pub_key_t *client_key,
    const struct ecc_priv_key_t *server_key, const struct asymmetric_params_t *ec_params,
    struct memref_t *secret);

int32_t soft_crypto_pbkdf2(const struct memref_t *password, const struct memref_t *salt,
    uint32_t iterations, uint32_t digest_type, struct memref_t *data_out);

#endif

