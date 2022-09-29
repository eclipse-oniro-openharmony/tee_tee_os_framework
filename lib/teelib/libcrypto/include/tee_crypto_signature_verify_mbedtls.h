/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: For signature verify
 * Create: 2022-04-14
 */

#ifndef TEE_CRYPTO_SIGNATURE_VERIFY_MBEDTLS_H
#define TEE_CRYPTO_SIGNATURE_VERIFY_MBEDTLS_H

#include <crypto_wrapper.h>
#include <tee_crypto_api.h>

TEE_Result tee_secure_img_release_verify(const uint8_t *hash, uint32_t hash_size, const uint8_t *signature,
    uint32_t signature_size, const rsa_pub_key_t *pub_key);

#endif
