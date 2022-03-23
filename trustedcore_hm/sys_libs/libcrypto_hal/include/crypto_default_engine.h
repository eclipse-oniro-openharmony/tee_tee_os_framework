/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Crypto API at driver adaptor.
 * Create: 2020-04-10
 */
#ifndef CRYPTO_DEFAULT_ENGINE_H
#define CRYPTO_DEFAULT_ENGINE_H

#include <crypto_driver_adaptor.h>

#define DX_CRYPTO   0
#define EPS_CRYPTO  1
#define SOFT_CRYPTO 2
#define SEC_CRYPTO  3

struct algorithm_engine_t {
    uint32_t             algorithm;
    uint32_t             engine;
};

#ifdef ASCEND_SEC_ENABLE
const struct algorithm_engine_t g_algorithm_engine[] = {
    { CRYPTO_TYPE_AES_ECB_NOPAD,                SEC_CRYPTO },
    { CRYPTO_TYPE_AES_CBC_NOPAD,                SEC_CRYPTO },
    { CRYPTO_TYPE_AES_ECB_PKCS5,                SEC_CRYPTO },
    { CRYPTO_TYPE_AES_CBC_PKCS5,                SEC_CRYPTO },
    { CRYPTO_TYPE_AES_CTR,                      SEC_CRYPTO },
    { CRYPTO_TYPE_SM4_CBC,                      SEC_CRYPTO },
    { CRYPTO_TYPE_SM4_CTR,                      SEC_CRYPTO },
    { CRYPTO_TYPE_HMAC_SHA1,                    SEC_CRYPTO },
    { CRYPTO_TYPE_HMAC_SHA224,                  SEC_CRYPTO },
    { CRYPTO_TYPE_HMAC_SHA256,                  SEC_CRYPTO },
    { CRYPTO_TYPE_HMAC_SHA384,                  SEC_CRYPTO },
    { CRYPTO_TYPE_HMAC_SHA512,                  SEC_CRYPTO },
    { CRYPTO_TYPE_HMAC_SM3,                     SEC_CRYPTO },
    { CRYPTO_TYPE_AES_GCM,                      SEC_CRYPTO },
    { CRYPTO_TYPE_DIGEST_SHA1,                  SEC_CRYPTO },
    { CRYPTO_TYPE_DIGEST_SHA224,                SEC_CRYPTO },
    { CRYPTO_TYPE_DIGEST_SHA256,                SEC_CRYPTO },
    { CRYPTO_TYPE_DIGEST_SHA384,                SEC_CRYPTO },
    { CRYPTO_TYPE_DIGEST_SHA512,                SEC_CRYPTO },
    { CRYPTO_TYPE_DIGEST_SM3,                   SEC_CRYPTO },
    { CRYPTO_TYPE_GENERATE_RANDOM,              SEC_CRYPTO },
};
const struct algorithm_engine_t g_generate_key_engine[] = {
    { 0,       SOFT_CRYPTO },
};
#elif defined DX_ENABLE
const struct algorithm_engine_t g_algorithm_engine[] = {
    { CRYPTO_TYPE_AES_XTS,                 DX_CRYPTO },
    { CRYPTO_TYPE_DES_ECB_NOPAD,           DX_CRYPTO },
    { CRYPTO_TYPE_DES_CBC_NOPAD,           DX_CRYPTO },
    { CRYPTO_TYPE_DES3_ECB_NOPAD,          DX_CRYPTO },
    { CRYPTO_TYPE_DES3_CBC_NOPAD,          DX_CRYPTO },
    { CRYPTO_TYPE_AES_CTS,                 DX_CRYPTO },
    { CRYPTO_TYPE_DH_DERIVE_SECRET,        DX_CRYPTO },
    { CRYPTO_TYPE_DES3_CBC_MAC_NOPAD,      DX_CRYPTO },
    { CRYPTO_TYPE_DES_CBC_MAC_NOPAD,       DX_CRYPTO },
    { CRYPTO_TYPE_GENERATE_RANDOM,         DX_CRYPTO },
};
const struct algorithm_engine_t g_generate_key_engine[] = {
    { CRYPTO_KEY_TYPE_DH_KEYPAIR,          DX_CRYPTO },
};
#else
const struct algorithm_engine_t g_algorithm_engine[] = {
    { 0,       SOFT_CRYPTO },
};
const struct algorithm_engine_t g_generate_key_engine[] = {
    { 0,       SOFT_CRYPTO },
};
#endif

#endif
