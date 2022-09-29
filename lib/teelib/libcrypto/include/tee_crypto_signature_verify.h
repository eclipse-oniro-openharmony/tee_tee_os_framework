/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: For signature verify
 * Create: 2021-07-31
 */

#ifndef TEE_CRYPTO_SIGNATURE_VERIFY_H
#define TEE_CRYPTO_SIGNATURE_VERIFY_H

#include <openssl/rsa.h>
#include <crypto_wrapper.h>
#include <tee_crypto_api.h>

uint32_t get_effective_size(const uint8_t *buff, uint32_t len);
TEE_Result tee_secure_img_release_verify(const uint8_t *hash, uint32_t hash_size, const uint8_t *signature,
    uint32_t signature_size, RSA *pub_key);
RSA *rsa_build_public_key(const rsa_pub_key_t *pub_key);

#endif
