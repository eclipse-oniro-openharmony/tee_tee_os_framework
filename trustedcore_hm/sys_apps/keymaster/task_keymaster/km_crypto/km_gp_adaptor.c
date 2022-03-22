/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster key transfer between keymaster and GP
 * Create: 2020-11-09
 */

#include "keymaster_defs.h"
#include "km_crypto_adaptor.h"
#include "km_types.h"
static keymaster_uint2uint g_3des_blockmode_gp_algorithm[] = {
    { KM_MODE_ECB, TEE_ALG_DES3_ECB_NOPAD },
    { KM_MODE_CBC, TEE_ALG_DES3_CBC_NOPAD }
};

keymaster_error_t check_block_mode(keymaster_block_mode_t block_mode, uint32_t *mode)
{
    if (mode == NULL) {
        tloge("null pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (look_up_table(g_3des_blockmode_gp_algorithm,
        sizeof(g_3des_blockmode_gp_algorithm) / sizeof(keymaster_uint2uint), block_mode, mode) != TEE_SUCCESS) {
        tloge("unsuppported block mode %u\n", block_mode);
        return KM_ERROR_UNSUPPORTED_BLOCK_MODE;
    }
    return KM_ERROR_OK;
}

static keymaster_uint2uint g_digest_gp_ec_algorithm[] = {
    { KM_DIGEST_SHA1, TEE_ALG_ECDSA_SHA1 },
    { KM_DIGEST_SHA_2_224, TEE_ALG_ECDSA_SHA224 },
    { KM_DIGEST_SHA_2_256, TEE_ALG_ECDSA_SHA256 },
    { KM_DIGEST_SHA_2_384, TEE_ALG_ECDSA_SHA384 },
    { KM_DIGEST_SHA_2_512, TEE_ALG_ECDSA_SHA512 }
};

keymaster_error_t get_ec_algorithm(const keymaster_digest_t digest, uint32_t *algorithm)
{
    if (algorithm == NULL) {
        tloge("null pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (look_up_table(g_digest_gp_ec_algorithm, sizeof(g_digest_gp_ec_algorithm) / sizeof(keymaster_uint2uint),
        digest, algorithm) != TEE_SUCCESS) {
        tloge("imcompatible digest %u\n", digest);
        return KM_ERROR_INCOMPATIBLE_DIGEST;
    }
    return KM_ERROR_OK;
}

static keymaster_uint2uint g_digest_gp_hmac_algorithm[] = {
    { KM_DIGEST_MD5, TEE_ALG_HMAC_MD5 },
    { KM_DIGEST_SHA1, TEE_ALG_HMAC_SHA1 },
    { KM_DIGEST_SHA_2_224, TEE_ALG_HMAC_SHA224 },
    { KM_DIGEST_SHA_2_256, TEE_ALG_HMAC_SHA256 },
    { KM_DIGEST_SHA_2_384, TEE_ALG_HMAC_SHA384 },
    { KM_DIGEST_SHA_2_512, TEE_ALG_HMAC_SHA512 }
};

keymaster_error_t get_hmac_algorithm(const keymaster_digest_t digest, uint32_t *algorithm)
{
    if (algorithm == NULL) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (look_up_table(g_digest_gp_hmac_algorithm, sizeof(g_digest_gp_hmac_algorithm) / sizeof(keymaster_uint2uint),
        digest, algorithm) != TEE_SUCCESS) {
        tloge("unsupported digest %u\n", digest);
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    return KM_ERROR_OK;
}

static const struct rsa_params_alogrithm g_rsa_params_algorithms[] = {
    /* rsa sign/verify */
    { KM_PAD_RSA_PKCS1_1_5_SIGN, KM_DIGEST_MD5, TEE_ALG_RSASSA_PKCS1_V1_5_MD5 },
    { KM_PAD_RSA_PKCS1_1_5_SIGN, KM_DIGEST_SHA1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1 },
    { KM_PAD_RSA_PKCS1_1_5_SIGN, KM_DIGEST_SHA_2_224, TEE_ALG_RSASSA_PKCS1_V1_5_SHA224 },
    { KM_PAD_RSA_PKCS1_1_5_SIGN, KM_DIGEST_SHA_2_256, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 },
    { KM_PAD_RSA_PKCS1_1_5_SIGN, KM_DIGEST_SHA_2_384, TEE_ALG_RSASSA_PKCS1_V1_5_SHA384 },
    { KM_PAD_RSA_PKCS1_1_5_SIGN, KM_DIGEST_SHA_2_512, TEE_ALG_RSASSA_PKCS1_V1_5_SHA512 },
    { KM_PAD_RSA_PSS, KM_DIGEST_MD5, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_MD5 },
    { KM_PAD_RSA_PSS, KM_DIGEST_SHA1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1 },
    { KM_PAD_RSA_PSS, KM_DIGEST_SHA_2_224, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224 },
    { KM_PAD_RSA_PSS, KM_DIGEST_SHA_2_256, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 },
    { KM_PAD_RSA_PSS, KM_DIGEST_SHA_2_384, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384 },
    { KM_PAD_RSA_PSS, KM_DIGEST_SHA_2_512, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512 },
    /* rsa encrypt/decrypt */
    { KM_PAD_RSA_OAEP, KM_DIGEST_SHA1, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1 },
    { KM_PAD_RSA_OAEP, KM_DIGEST_SHA_2_224, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224 },
    { KM_PAD_RSA_OAEP, KM_DIGEST_SHA_2_256, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 },
    { KM_PAD_RSA_OAEP, KM_DIGEST_SHA_2_384, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384 },
    { KM_PAD_RSA_OAEP, KM_DIGEST_SHA_2_512, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512 },
    { KM_PAD_RSA_OAEP, KM_DIGEST_SHA1, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1 },
    { KM_PAD_RSA_PKCS1_1_5_ENCRYPT, KM_DIGEST_NONE, TEE_ALG_RSAES_PKCS1_V1_5 },
    { KM_PAD_NONE, KM_DIGEST_NONE, TEE_ALG_RSA_NOPAD },
};

keymaster_error_t get_rsa_algorithm(const keymaster_padding_t padding, const keymaster_digest_t digest,
    uint32_t *algorithm)
{
    if (algorithm == NULL) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    uint32_t i;
    uint32_t count = sizeof(g_rsa_params_algorithms) / sizeof(struct rsa_params_alogrithm);
    uint8_t padding_found_flag = 0;
    uint8_t digest_found_flag = 0;
    for (i = 0; i < count; i++) {
        if (padding == g_rsa_params_algorithms[i].padding) {
            padding_found_flag = 1;
            if (digest == g_rsa_params_algorithms[i].digest || g_rsa_params_algorithms[i].digest == KM_DIGEST_NONE) {
                *algorithm = g_rsa_params_algorithms[i].gp_algorithm;
                tlogd("algorithm converted success, %u\n", *algorithm);
                return KM_ERROR_OK;
            }
        }
    }
    if (padding_found_flag != 1) {
        tloge("unsupported padding, %u\n", padding);
        return KM_ERROR_INCOMPATIBLE_PADDING_MODE;
    }
    if (digest_found_flag != 1) {
        tloge("unsupported digest mode, %u\n", digest);
        return KM_ERROR_INCOMPATIBLE_DIGEST;
    }
    tloge("invalid params\n");
    return KM_ERROR_UNSUPPORTED_ALGORITHM;
}

static keymaster_uint2uint g_km2gp_purpose[] = {
    { KM_PURPOSE_SIGN, TEE_MODE_SIGN },
    { KM_PURPOSE_VERIFY, TEE_MODE_VERIFY },
    { KM_PURPOSE_ENCRYPT, TEE_MODE_ENCRYPT },
    { KM_PURPOSE_DECRYPT, TEE_MODE_DECRYPT }
};

keymaster_error_t get_ec_pupose(const keymaster_purpose_t purpose, TEE_OperationMode *mode)
{
    if (mode == NULL) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }

    bool check_fail = (purpose != KM_PURPOSE_SIGN && purpose != KM_PURPOSE_VERIFY);
    if (check_fail) {
        tloge("invalid purpose\n");
        return KM_ERROR_INCOMPATIBLE_PURPOSE;
    }
    if (look_up_table(g_km2gp_purpose, sizeof(g_km2gp_purpose) / sizeof(keymaster_uint2uint), purpose, mode) !=
        TEE_SUCCESS) {
        tloge("invalid purpose %u", purpose);
        return KM_ERROR_INCOMPATIBLE_PURPOSE;
    }
    return KM_ERROR_OK;
}

keymaster_error_t get_rsa_purpose(const keymaster_purpose_t purpose, TEE_OperationMode *mode)
{
    if (mode == NULL) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (look_up_table(g_km2gp_purpose, sizeof(g_km2gp_purpose) / sizeof(keymaster_uint2uint), purpose, mode) !=
        TEE_SUCCESS) {
        tloge("invalid purpose %u", purpose);
        return KM_ERROR_INCOMPATIBLE_PURPOSE;
    }
    return KM_ERROR_OK;
}

keymaster_error_t get_sym_purpose(keymaster_purpose_t purpose, TEE_OperationMode *mode)
{
    if (mode == NULL) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    bool check_fail = (purpose != KM_PURPOSE_ENCRYPT && purpose != KM_PURPOSE_DECRYPT);
    if (check_fail) {
        tloge("invalid purpose\n");
        return KM_ERROR_INCOMPATIBLE_PURPOSE;
    }
    if (look_up_table(g_km2gp_purpose, sizeof(g_km2gp_purpose) / sizeof(keymaster_uint2uint), purpose, mode) !=
        TEE_SUCCESS) {
        tloge("invalid purpose %u", purpose);
        return KM_ERROR_INCOMPATIBLE_PURPOSE;
    }
    return KM_ERROR_OK;
}

static keymaster_uint2uint g_gp2km_ec_curve[] = {
    { TEE_ECC_CURVE_NIST_P224, KM_EC_CURVE_P_224 },
    { TEE_ECC_CURVE_NIST_P256, KM_EC_CURVE_P_256 },
    { TEE_ECC_CURVE_NIST_P384, KM_EC_CURVE_P_384 },
    { TEE_ECC_CURVE_NIST_P521, KM_EC_CURVE_P_521 }
};

keymaster_ec_curve_t ec_nist_curve2kmcurve(TEE_ECC_CURVE ec_curve)
{
    uint32_t index = 0;
    for (; index < (sizeof(g_gp2km_ec_curve) / sizeof(keymaster_uint2uint)); index++)
        if (ec_curve == g_gp2km_ec_curve[index].src)
            return (keymaster_ec_curve_t)g_gp2km_ec_curve[index].dest;

    tloge("invalid ec_curve %d\n", ec_curve);
    return KM_EC_CURVE_P_OFF;
}

struct digest_mapping {
    keymaster_digest_t km_digest;
    uint32_t gp_digest;
};

static struct digest_mapping g_km2gp_digest[] = {
    {KM_DIGEST_MD5, TEE_ALG_MD5},
    {KM_DIGEST_SHA1, TEE_ALG_SHA1},
    {KM_DIGEST_SHA_2_224, TEE_ALG_SHA224},
    {KM_DIGEST_SHA_2_256, TEE_ALG_SHA256},
    {KM_DIGEST_SHA_2_384, TEE_ALG_SHA384},
    {KM_DIGEST_SHA_2_512, TEE_ALG_SHA512}
};

uint32_t keymaster_get_digest_hash(const uint32_t digest_mode)
{
    uint32_t i;
    for (i = 0; i < sizeof(g_km2gp_digest) / sizeof(struct digest_mapping); i++) {
        if (g_km2gp_digest[i].km_digest == digest_mode)
            return g_km2gp_digest[i].gp_digest;
    }
    return 0;
}

struct aes_algorithm_params {
    keymaster_block_mode_t block_mode;
    keymaster_padding_t padding;
    uint32_t gp_algorithm;
};

static struct aes_algorithm_params g_gp_aes_algorithms[] = {
    { KM_MODE_ECB, KM_PAD_NONE, TEE_ALG_AES_ECB_NOPAD },
    { KM_MODE_ECB, KM_PAD_PKCS7, TEE_ALG_AES_ECB_PKCS5 },
    { KM_MODE_CBC, KM_PAD_NONE, TEE_ALG_AES_CBC_NOPAD },
    { KM_MODE_CBC, KM_PAD_PKCS7, TEE_ALG_AES_CBC_PKCS5 },
    { KM_MODE_CTR, KM_PAD_NONE, TEE_ALG_AES_CTR },
    { KM_MODE_GCM, KM_PAD_NONE, TEE_ALG_AES_GCM }
};

keymaster_error_t get_aes_algorithm(keymaster_block_mode_t block_mode, keymaster_padding_t padding, uint32_t *alg)
{
    if (alg == NULL) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    uint32_t i;
    bool block_mode_flag = false;
    bool padding_flag = false;
    for (i = 0; i < sizeof(g_gp_aes_algorithms) / sizeof(struct aes_algorithm_params); i++) {
        if (g_gp_aes_algorithms[i].block_mode == block_mode) {
            block_mode_flag = true;
            if (g_gp_aes_algorithms[i].padding == padding) {
                *alg = g_gp_aes_algorithms[i].gp_algorithm;
                return KM_ERROR_OK;
            }
        }
    }
    if (!block_mode_flag) {
        tloge("invalid block_mode\n");
        return KM_ERROR_UNSUPPORTED_BLOCK_MODE;
    }
    if (!padding_flag) {
        tloge("invalid padding mode\n");
        return KM_ERROR_INCOMPATIBLE_PADDING_MODE;
    }
    tloge("unsupported params\n");
    return KM_ERROR_UNIMPLEMENTED;
}