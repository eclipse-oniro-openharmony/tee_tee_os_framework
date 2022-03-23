/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: soft engine in boringssl
 * Create: 2019-06-14
 */

#ifndef __CRYPTO_INNER_INTERFACE_H__
#define __CRYPTO_INNER_INTERFACE_H__

#include "crypto_wrapper.h"
#define TBL_HEADER_FIX_LEN 16
#define SIGNING_ALGO_LEN   50
#define DIGEST_MAX_LEN     64
#define SIG_MAX_LEN        512
#define ALGO_TLV_MAX_LEN   50
#define HASH_LEN           32

#ifndef MBEDTLS_ENABLE
#include <openssl/rsa.h>

RSA *build_boringssl_pub_key(rsa_pub_key_t *pub);

RSA *build_boringssl_priv_key(rsa_priv_key_t *priv);

TEE_Result ecc_pubkey_tee_to_boring(void *publickey, EC_KEY **eckey);
#endif

TEE_Result ecc_privkey_tee_to_boring(void *priv, void **eckey);

int32_t get_class_ecc_key(uint8_t *priv, uint32_t priv_len);

int32_t ec_nid_tom2boringssl(uint32_t domain);

int32_t get_keytype_from_sp(const uint8_t *in, uint32_t inlen);

int32_t generate_rsa_from_secret(rsa_priv_key_t *rsa, uint32_t nbits, uint8_t *secret, uint32_t secret_len,
    const uint8_t *file_name);

int32_t derive_private_key_from_secret(void *priv, uint8_t *secret, uint32_t secret_len, uint32_t bits,
    uint32_t keytype, uint8_t *file_name);

#endif
