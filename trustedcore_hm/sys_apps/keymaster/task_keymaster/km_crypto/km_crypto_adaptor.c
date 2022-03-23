/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster crypto params adaptor
 * Create: 2020-11-09
 */

#include "keymaster_defs.h"
#include "km_types.h"
#include "km_tag_operation.h"
#include "crypto_wrapper.h"
#ifdef BORINGSSL_ENABLE
#include "openssl/nid.h"
#else
#include "openssl/obj_mac.h"
#endif

TEE_Result look_up_table(const keymaster_uint2uint *buff, uint32_t buff_len, uint32_t src, uint32_t *dst)
{
    bool check_fail = (buff == NULL || dst == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t index = 0;
    for (; index < buff_len; index++)
        if (src == buff[index].src) {
            *dst = buff[index].dest;
            return TEE_SUCCESS;
        }

    tloge("look up src value %u failed\n", src);
    return TEE_ERROR_BAD_PARAMETERS;
}

static keymaster_uint2uint g_keysize_gp_eccurve[] = {
    { 192, TEE_ECC_CURVE_NIST_P192 },
    { 224, TEE_ECC_CURVE_NIST_P224 },
    { 256, TEE_ECC_CURVE_NIST_P256 },
    { 384, TEE_ECC_CURVE_NIST_P384 },
    { 521, TEE_ECC_CURVE_NIST_P521 }
};
int32_t ec_keysize2nist_curve(uint32_t key_size, TEE_ECC_CURVE *ecc_curv)
{
    if (ecc_curv == NULL) {
        tloge("null pointer\n");
        return -1;
    }
    if (look_up_table(g_keysize_gp_eccurve, sizeof(g_keysize_gp_eccurve) / sizeof(keymaster_uint2uint),
        key_size, ecc_curv) != TEE_SUCCESS) {
        tloge("invalid keysize %u\n", key_size);
        return -1;
    }
    return 0;
}

int32_t ec_nist_curve2key_size(TEE_ECC_CURVE ecc_curv, uint32_t *key_size)
{
    if (key_size == NULL) {
        tloge("null pointer\n");
        return -1;
    }

    uint32_t index = 0;
    for (; index < (sizeof(g_keysize_gp_eccurve) / sizeof(keymaster_uint2uint)); index++)
        if (ecc_curv == g_keysize_gp_eccurve[index].dest) {
            *key_size = g_keysize_gp_eccurve[index].src;
            return 0;
        }

    tloge("invalid curve id %u\n", ecc_curv);
    return -1;
}
static keymaster_uint2uint g_km_eccurve_keysize[] = {
    { KM_EC_CURVE_P_224, 224 },
    { KM_EC_CURVE_P_256, 256 },
    { KM_EC_CURVE_P_384, 384 },
    { KM_EC_CURVE_P_521, 521 }
};
int32_t km_ec_domain_id_to_keysize(keymaster_ec_curve_t domain, uint32_t *key_size)
{
    if (key_size == NULL) {
        tloge("key_size is null pointer\n");
        return -1;
    }
    if (look_up_table(g_km_eccurve_keysize, sizeof(g_km_eccurve_keysize) / sizeof(keymaster_uint2uint),
        domain, key_size) != TEE_SUCCESS) {
        tloge("invalid domain id %d\n", domain);
        return -1;
    }
    return 0;
}

TEE_Result get_key_obj_type(keymaster_algorithm_t algorithm, keymaster_digest_t digest_mode,
    uint32_t *object_type)
{
    if (object_type == NULL) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    keymaster_uint2uint algorithm_to_obj_type[] = {
        { KM_ALGORITHM_EC, TEE_TYPE_ECDSA_KEYPAIR },
        { KM_ALGORITHM_RSA, TEE_TYPE_RSA_KEYPAIR },
        { KM_ALGORITHM_AES, TEE_TYPE_AES },
        { KM_ALGORITHM_TRIPLE_DES, TEE_TYPE_DES3 },
    };
    keymaster_uint2uint hmac_hash_obj_type[] = {
        { KM_DIGEST_MD5,       TEE_TYPE_HMAC_MD5 },
        { KM_DIGEST_SHA1,      TEE_TYPE_HMAC_SHA1 },
        { KM_DIGEST_SHA_2_224, TEE_TYPE_HMAC_SHA224 },
        { KM_DIGEST_SHA_2_256, TEE_TYPE_HMAC_SHA256 },
        { KM_DIGEST_SHA_2_384, TEE_TYPE_HMAC_SHA384 },
        { KM_DIGEST_SHA_2_512, TEE_TYPE_HMAC_SHA512 }
    };
    if (algorithm != KM_ALGORITHM_HMAC) {
        if (look_up_table(algorithm_to_obj_type, sizeof(algorithm_to_obj_type) / sizeof(keymaster_uint2uint),
            algorithm, object_type) != TEE_SUCCESS) {
            tloge("unsupport algorithm %d\n", algorithm);
            return TEE_ERROR_BAD_PARAMETERS;
        }
    } else {
        if (look_up_table(hmac_hash_obj_type, sizeof(hmac_hash_obj_type) / sizeof(keymaster_uint2uint),
            digest_mode, object_type) != TEE_SUCCESS) {
            tloge("unsupported hmac key types, hash type %d\n", digest_mode);
            return KM_ERROR_UNSUPPORTED_DIGEST;
        }
    }
    return TEE_SUCCESS;
}

TEE_Result get_key_object(keymaster_algorithm_t algorithm, uint32_t key_size,
    const keymaster_key_param_set_t *params_hw_enforced, TEE_ObjectHandle *key_obj)
{
    /* NOTICE: this function allocate key_obj, it should be freed by caller */
    if (key_obj == NULL) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (*key_obj != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(*key_obj);
        *key_obj = TEE_HANDLE_NULL;
    }
    keymaster_digest_t digest;
    bool condition = (algorithm == KM_ALGORITHM_HMAC &&
        get_key_param(KM_TAG_DIGEST, &digest, params_hw_enforced) == -1);
    if (condition) {
        tloge("get digest tag length from key failed\n");
        return (TEE_Result)KM_ERROR_UNSUPPORTED_DIGEST;
    }
    uint32_t object_type;
    TEE_Result ret = get_key_obj_type(algorithm, digest, &object_type);
    if (ret != TEE_SUCCESS) {
        tloge("get key object type failed, algorithm %d, digest %u\n", algorithm, digest);
        return ret;
    }
    ret = TEE_AllocateTransientObject(object_type, key_size, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("allocate transient object failed\n");
        return ret;
    }
    return TEE_SUCCESS;
}

int32_t get_hash_block_size(keymaster_digest_t digest, uint32_t *block_size)
{
    if (block_size == NULL) {
        tloge("block_size is null");
        return -1;
    }
    bool small_block_digest = (digest == KM_DIGEST_MD5 || digest == KM_DIGEST_SHA1 || digest == KM_DIGEST_SHA_2_224 ||
        digest == KM_DIGEST_SHA_2_256);
    bool big_block_digest = (digest == KM_DIGEST_SHA_2_384 || digest == KM_DIGEST_SHA_2_512);
    if (small_block_digest) {
        *block_size = HASH_BLOCK_SIZE_64;
        return 0;
    }
    if (big_block_digest) {
        *block_size = HASH_BLOCK_SIZE_128;
        return 0;
    }
    tloge("invalid digest\n");
    return -1;
}

static keymaster_uint2uint g_hash_bits[] = {
    { KM_DIGEST_NONE,      0 },
    { KM_DIGEST_MD5,       128 },
    { KM_DIGEST_SHA1,      160 },
    { KM_DIGEST_SHA_2_224, 224 },
    { KM_DIGEST_SHA_2_256, 256 },
    { KM_DIGEST_SHA_2_384, 384 },
    { KM_DIGEST_SHA_2_512, 512 }
};

keymaster_error_t hash_mode_to_size_bits(keymaster_digest_t digest, uint32_t *digest_len_bits)
{
    if (digest_len_bits == NULL) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (look_up_table(g_hash_bits, sizeof(g_hash_bits) / sizeof(keymaster_uint2uint),
        digest, digest_len_bits) != TEE_SUCCESS) {
        tloge("unsupported digest %u\n", digest);
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    return KM_ERROR_OK;
}

int32_t get_real_hash_len(keymaster_digest_t digest, uint32_t *hash_buff_len)
{
    if (hash_buff_len == NULL) {
        tloge("null pointer\n");
        return -1;
    }
    if (digest == KM_DIGEST_NONE)
        return 0;
    uint32_t digest_len_bits;
    if (hash_mode_to_size_bits(digest, &digest_len_bits) != KM_ERROR_OK) {
        tloge("get hash bits failed\n");
        return -1;
    }
    if (*hash_buff_len < digest_len_bits / BITS_ONE_BYTE) {
        tloge("input hash buff len %u is too small\n", *hash_buff_len);
        return -1;
    }
    *hash_buff_len = digest_len_bits / BITS_ONE_BYTE;
    return 0;
}
