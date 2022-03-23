/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster crypto params check
 * Create: 2020-11-09
 */

#include "keymaster_defs.h"
#include "km_types.h"
#include "tee_crypto_api.h"
#include "crypto_wrapper.h"
#include "keyblob.h"
#include "km_keynode.h"
#include "km_tag_operation.h"
#include "km_crypto_adaptor.h"
#include "km_crypto_check.h"
keymaster_error_t check_hmc_tag_len(key_auth *key_node, const keymaster_key_param_set_t *params_enforced,
    const keymaster_key_param_set_t *hw_enforced, uint32_t *tag_len)
{
    uint32_t min_tag_len;
    int ret;
    ret = get_key_param(KM_TAG_MIN_MAC_LENGTH, &min_tag_len, hw_enforced);
    if (ret == -1) {
        tloge("get gcm min tag length from key failed\n");
        return KM_ERROR_MISSING_MIN_MAC_LENGTH;
    } else {
        key_node->min_tag_len = min_tag_len; /* already check in generate */
    }

    ret = get_key_param(KM_TAG_MAC_LENGTH, tag_len, params_enforced);
    if (ret == -1) {
        if (key_node->purpose == KM_PURPOSE_SIGN) {
            tloge("get mac tag length failed\n");
            return KM_ERROR_MISSING_MAC_LENGTH;
        }
    } else {
        uint32_t hash_size_bits = 0;
        if (hash_mode_to_size_bits(key_node->digest, &hash_size_bits) != KM_ERROR_OK) {
            tloge("get hash bits failed\n");
            return (TEE_Result)KM_ERROR_UNSUPPORTED_DIGEST;
        }
        if (*tag_len % BITS_ONE_BYTE != 0 || *tag_len > hash_size_bits) {
            tloge("mac length is invalid\n");
            return KM_ERROR_UNSUPPORTED_MAC_LENGTH;
        }
        if (*tag_len < min_tag_len) {
            tloge("mac length small than min_tag_len\n");
            return KM_ERROR_INVALID_MAC_LENGTH;
        }
    }

    return KM_ERROR_OK;
}

/* km_params check rules: 1.not input reduplicate TAG; 2.not input TAG that keymaster TA generated; */
static int32_t check_multi_tag(keymaster_tag_t tag, const keymaster_key_param_set_t *params_set)
{
    if (params_set == NULL)
        return 0;
    uint32_t i;
    uint32_t count = 0;
    keymaster_key_param_t *params = (keymaster_key_param_t *)((uint8_t *)params_set + sizeof(params_set->length));

    for (i = 0; i < params_set->length; i++) {
        if (tag == params[i].tag)
            count++;
        if (count > 1)
            return -1;
    }
    return 0;
}

static int32_t check_multi_tag_params(keymaster_tag_t tag, const keymaster_key_param_set_t *hw_params_set)
{
    if (hw_params_set == NULL)
        return 0;
    keymaster_key_param_set_t *sw_params_set = (keymaster_key_param_set_t *)((uint8_t *)hw_params_set +
        (sizeof(keymaster_key_param_t) * hw_params_set->length) + sizeof(uint32_t));
    /* check multiple tag which is not allowed */
    bool check_fail = ((check_multi_tag(tag, hw_params_set) < 0) || (check_multi_tag(tag, sw_params_set) < 0));
    if (check_fail) {
        tloge("multiple KM_TAG_DIGEST in params\n");
        return -1;
    }

    return 0;
}

keymaster_error_t check_ec_padding_digest_purpose(keymaster_padding_t *padding, keymaster_digest_t *digest,
    keymaster_purpose_t purpose, const keymaster_key_param_set_t *hw_enforced,
    const keymaster_key_param_set_t *params_enforced)
{
    bool check_fail = (padding == NULL || digest == NULL || hw_enforced == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    check_fail = (purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_DECRYPT);
    if (check_fail) {
        tloge("purpose unsuppported\n");
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }
    int ret = get_key_param(KM_TAG_PADDING, padding, hw_enforced);
    if (ret != 0)
        tlogd("get_key_param of padding failed\n");

    ret = get_key_param(KM_TAG_DIGEST, digest, params_enforced);
    if (ret != 0)
        tlogd("get_key_param of keymaster_digest failed\n");
    check_fail = (purpose == KM_PURPOSE_SIGN &&
        is_key_param_suport(KM_TAG_DIGEST, (void *)digest, hw_enforced) == 0);
    if (check_fail) {
        tloge("do not support digest 0x%x\n", *digest);
        return (keymaster_error_t)TEE_ERROR_BAD_PARAMETERS;
    }
    return KM_ERROR_OK;
}

keymaster_error_t check_rsa_digest_mode(keymaster_padding_t padding, keymaster_digest_t digest, uint32_t key_size)
{
    uint32_t hash_bits;
    /* check digest mode for VTS */
    if (padding == KM_PAD_RSA_PSS) {
        if (hash_mode_to_size_bits(digest, &hash_bits) != KM_ERROR_OK) {
            tloge("get hash size bits failed\n");
            return KM_ERROR_INCOMPATIBLE_DIGEST;
        }
        if (key_size < hash_bits * HASH_BITS_TWO + HASH_BITS_SIZE) {
            tloge("keysize too small\n");
            return KM_ERROR_INCOMPATIBLE_DIGEST;
        }
    }
    return KM_ERROR_OK;
}
keymaster_error_t check_rsa_padding_params(keymaster_padding_t *padding,
    const keymaster_key_param_set_t *params_enforced, keymaster_purpose_t purpose,
    const keymaster_key_param_set_t *hw_enforced)
{
    bool check_fail = (padding == NULL || params_enforced == NULL || hw_enforced == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (get_key_param(KM_TAG_PADDING, padding, params_enforced)) {
        tloge("get_key_param of keymaster padding failed\n");
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }
    if (*padding > KM_PAD_RSA_PKCS1_1_5_SIGN) {
        tloge("invalid padding %d in rsa\n", *padding);
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }
    check_fail = ((purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_DECRYPT) &&
        (is_key_param_suport(KM_TAG_PADDING, (void *)padding, hw_enforced) == 0));
    if (check_fail) {
        tloge("do not support padding 0x%x\n", *padding);
        return KM_ERROR_INCOMPATIBLE_PADDING_MODE;
    }

    return KM_ERROR_OK;
}

static keymaster_error_t check_rsa_decrypt_digest_auth(keymaster_purpose_t purpose, const keymaster_digest_t *digest,
    const keymaster_key_param_set_t *hw_enforced)
{
    bool check_fail = (digest == NULL || hw_enforced == NULL);
    if (check_fail) {
        tloge("null pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    /* when decrypt: we should check whether the digest is authorized if digest is provided */
    check_fail = (purpose == KM_PURPOSE_DECRYPT &&
        is_key_param_suport(KM_TAG_DIGEST, (void *)digest, hw_enforced) == 0);
    if (check_fail) {
        tloge("purpose 0x%x do not support digest NONE 0x%x\n", purpose, *digest);
        return (keymaster_error_t)TEE_ERROR_BAD_PARAMETERS;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t check_rsa_sign_digest_auth(keymaster_purpose_t purpose, const keymaster_digest_t *digest,
    const keymaster_key_param_set_t *hw_enforced)
{
    bool check_fail = (digest == NULL || hw_enforced == NULL);
    if (check_fail) {
        tloge("null pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    /* when sign: we should check whether the digest is authorized */
    check_fail = (purpose == KM_PURPOSE_SIGN &&
        is_key_param_suport(KM_TAG_DIGEST, (void *)digest, hw_enforced) == 0);
    if (check_fail) {
        tloge("purpose 0x%x do not support digest NONE 0x%x\n", purpose, *digest);
        return (keymaster_error_t)TEE_ERROR_BAD_PARAMETERS;
    }
    return KM_ERROR_OK;
}

keymaster_error_t check_rsa_diagest_params(keymaster_padding_t padding, keymaster_purpose_t purpose,
    keymaster_digest_t *digest, const keymaster_key_param_set_t *params_enforced,
    const keymaster_key_param_set_t *hw_enforced)
{
    bool condition = (digest == NULL || params_enforced == NULL || hw_enforced == NULL);
    if (condition) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    int ret = get_key_param(KM_TAG_DIGEST, digest, params_enforced);
    keymaster_error_t km_ret;
    if (ret != 0) {
        tloge("get_key_param of keymaster_digest failed\n");
        condition = (padding == KM_PAD_RSA_OAEP || padding == KM_PAD_RSA_PSS);
        if (condition) {
            tloge("pss padding need digest\n");
            return KM_ERROR_UNSUPPORTED_DIGEST;
        }
    } else {
        km_ret = check_rsa_decrypt_digest_auth(purpose, digest, hw_enforced);
        if (km_ret != KM_ERROR_OK)
            return km_ret;
    }
    /* digest has initial value set by caller */
    return check_rsa_sign_digest_auth(purpose, digest, hw_enforced);
}

keymaster_error_t check_rsa_digest_is_valid(keymaster_padding_t padding, keymaster_digest_t digest)
{
    bool check_fail = (((padding == KM_PAD_RSA_OAEP || padding == KM_PAD_RSA_PSS) && digest == KM_DIGEST_NONE) ||
        (padding == KM_PAD_NONE && digest != KM_DIGEST_NONE));
    if (check_fail) {
        tloge("padding_mode %u and digest %u incompatible\n", padding, digest);
        return KM_ERROR_INCOMPATIBLE_DIGEST;
    }
    return KM_ERROR_OK;
}

keymaster_error_t check_operation_rsa_update(const key_auth *key_node, uint32_t in_size)
{
    if (key_node->use_soft == true) {
        rsa_priv_key_t *priv = (rsa_priv_key_t *)key_node->key1;
        if (((UINT32_MAX - key_node->data_size) < in_size) || ((key_node->data_size + in_size) > priv->n_len)) {
            tloge("invalid rsa input data length:%u/%u\n", key_node->data_size + in_size, priv->n_len);
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
    } else {
        TEE_OperationHandle rsa_operation = (TEE_OperationHandle)key_node->crypto_ctxt;
        uint32_t mod_len = rsa_operation->keySize;
        if (((UINT32_MAX - key_node->data_size) < in_size) || ((key_node->data_size + in_size) > mod_len)) {
            tloge("invalid rsa input data length:%u/%u\n", key_node->data_size + in_size, mod_len);
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
    }
    return KM_ERROR_OK;
}

int32_t check_padding_for_rsa_enc_dec(keymaster_padding_t padding)
{
    uint32_t index = 0;
    uint32_t support_padding_list[] = { KM_PAD_NONE, KM_PAD_RSA_OAEP, KM_PAD_RSA_PKCS1_1_5_ENCRYPT };

    for (; index < (sizeof(support_padding_list) / sizeof(uint32_t)); index++)
        if (padding == support_padding_list[index])
            return 0;

    return -1;
}

int32_t check_purpose_for_rsa_enc_dec(keymaster_purpose_t purpose)
{
    uint32_t index = 0;
    uint32_t support_purpose_list[] = { KM_PURPOSE_ENCRYPT, KM_PURPOSE_DECRYPT };

    for (; index < (sizeof(support_purpose_list) / sizeof(uint32_t)); index++)
        if (purpose == support_purpose_list[index])
            return 0;

    return -1;
}

int32_t check_padding_for_rsa_sign_verify(keymaster_padding_t padding)
{
    uint32_t index = 0;
    uint32_t support_padding_list[] = { KM_PAD_NONE, KM_PAD_RSA_PSS, KM_PAD_RSA_PKCS1_1_5_SIGN };

    for (; index < (sizeof(support_padding_list) / sizeof(uint32_t)); index++)
        if (padding == support_padding_list[index])
            return 0;

    return -1;
}

int32_t check_purpose_for_rsa_sign_verify(keymaster_purpose_t purpose)
{
    uint32_t index = 0;
    uint32_t support_purpose_list[] = { KM_PURPOSE_SIGN, KM_PURPOSE_VERIFY };

    for (; index < (sizeof(support_purpose_list) / sizeof(uint32_t)); index++)
        if (purpose == support_purpose_list[index])
            return 0;

    return -1;
}

keymaster_error_t check_gcm_tag_len(uint32_t block_mode, const keymaster_key_param_set_t *params_enforced,
    const keymaster_key_param_set_t *hw_enforced, uint32_t *tag_len, uint32_t *min_tag_len)
{
    /* add gcm by soft crypt engine check tag len invalid */
    if (block_mode != KM_MODE_GCM)
        return KM_ERROR_OK;
    tlogd("block mode is GCM\n");
    if (get_key_param(KM_TAG_MIN_MAC_LENGTH, min_tag_len, hw_enforced) != 0) {
        tloge("get min mac length tag length from key failed\n");
        return KM_ERROR_MISSING_MIN_MAC_LENGTH;
    }
    /* It must be a multiple of 8 */
    bool check_fail = (*min_tag_len % BITS_ONE_BYTE != 0 || *min_tag_len < MIN_TAG_LEN || *min_tag_len > MAX_TAG_LEN);
    if (check_fail) {
        tloge("unspport min mac length %u\n", *min_tag_len);
        return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;
    }

    if (get_key_param(KM_TAG_MAC_LENGTH, tag_len, params_enforced) != 0) {
        tloge("get mac length failed\n");
        return KM_ERROR_MISSING_MAC_LENGTH;
    }
    /* For MAC lengths greater than 128 or non-multiples of 8, return KM_ERROR_UNSUPPORTED_MAC_LENGTH */
    if (*tag_len % BITS_ONE_BYTE != 0 || *tag_len > MAX_TAG_LEN) {
        tloge("unsupport mac length %u\n", *tag_len);
        return KM_ERROR_UNSUPPORTED_MAC_LENGTH;
    }

    /* For values less than the  mini mac length, return KM_ERROR_INVALID_MAC_LENGTH. */
    if (*tag_len < *min_tag_len) {
        tloge("tag_len %u is invalid\n", *tag_len);
        return KM_ERROR_INVALID_MAC_LENGTH;
    }

    return KM_ERROR_OK;
}

int32_t check_ec_keysize_bits(uint32_t key_size_bits)
{
    uint32_t i;
    uint32_t valid_sizes[] = { 192, 224, 256, 384, 521 };
    for (i = 0; i < sizeof(valid_sizes) / sizeof(valid_sizes[0]); i++)
        if (key_size_bits == valid_sizes[i])
            return 0;
    tloge("ec key size bits %u is unsupported\n", key_size_bits);
    return -1;
}

int32_t check_rsa_keysize_bits(uint32_t key_size_bits)
{
    bool check_fail = ((key_size_bits == 0) || (key_size_bits % KM_BYTE_SIZE_8 != 0) ||
        (key_size_bits > KM_KEY_SIZE_4096));
    if (check_fail) {
        tloge("rsa key size bits %u is unsupported\n", key_size_bits);
        return -1;
    }
    return 0;
}

int32_t check_aes_keysize_bits(uint32_t key_size_bits)
{
    uint32_t valid_sizes[] = { 128, 192, 256 };
    uint32_t i;
    for (i = 0; i < (sizeof(valid_sizes) / sizeof(valid_sizes[0])); i++)
        if (key_size_bits == valid_sizes[i]) {
            tlogd("key size bits %u is valid\n", key_size_bits);
            return 0;
        }
    tloge("aes key size bits %u is unsupported\n", key_size_bits);
    return -1;
}

int32_t check_3des_keysize_bits(uint32_t key_size_bits)
{
    const uint32_t valid_sizes = KM_KEY_SIZE_192;
    if (key_size_bits == valid_sizes)
        return 0;
    tloge("3des key size bits %u is unsupported\n", key_size_bits);
    return -1;
}

int32_t check_hmac_keysize_bits(uint32_t key_size_bits)
{
    bool check_fail = ((key_size_bits < KM_MAC_MIN_TAG) || ((key_size_bits % KM_BYTE_SIZE_8) != 0));
    if (check_fail) {
        tloge("hmac key size bits %u is unsupported\n", key_size_bits);
        return -1;
    }
    return 0;
}

/*
 * In M, keymaster add many tags(keymaster_defs.h) for keymaster enforcement,
 * but we need not to implemnt all of them. And we could make sure the security
 * because of TEE. What we need to notice is keymaster should be worked with
 * real different scene compatibility
 */
int32_t check_algorithm_keysize(keymaster_algorithm_t algorithm, uint32_t key_size_bits)
{
    /* input key size is in bits */
    if (algorithm == KM_ALGORITHM_EC)
        return check_ec_keysize_bits(key_size_bits);
    else if (algorithm == KM_ALGORITHM_RSA)
        return check_rsa_keysize_bits(key_size_bits);
    else if (algorithm == KM_ALGORITHM_AES)
        return check_aes_keysize_bits(key_size_bits);
    else if (algorithm == KM_ALGORITHM_TRIPLE_DES)
        return check_3des_keysize_bits(key_size_bits);
    else if (algorithm == KM_ALGORITHM_HMAC)
        return check_hmac_keysize_bits(key_size_bits);

    tloge("algorithm is %x, key size bits is %u\n", algorithm, key_size_bits);
    return -1;
}

TEE_Result check_key_size_bits(keymaster_algorithm_t algorithm, uint32_t key_size_bits,
    const keymaster_key_param_set_t *params_hw_enforced)
{
    if (params_hw_enforced == NULL) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* check ecc curve and keysize is matched */
    if (algorithm == KM_ALGORITHM_EC) {
        uint32_t ec_curve_value = 0;
        uint32_t temp_keysize = 0;
        int32_t ret = get_key_param(KM_TAG_EC_CURVE, &ec_curve_value, params_hw_enforced);
        if (ret == 0) {
            if (km_ec_domain_id_to_keysize((keymaster_ec_curve_t)ec_curve_value, &temp_keysize) != 0) {
                tloge("get key_size from ec_curve failed\n");
                return (TEE_Result)KM_ERROR_INVALID_ARGUMENT;
            }
            if (key_size_bits != temp_keysize) {
                tloge("ec curve and keysize mismatch, km ec curv %u\n", ec_curve_value);
                return (TEE_Result)KM_ERROR_INVALID_ARGUMENT;
            }
        }
    }
    tlogd("key size is %u bits\n", key_size_bits);
    /* input check */
    if (check_algorithm_keysize(algorithm, key_size_bits) != 0) {
        tloge("algorithm key size invalid\n");
        return (TEE_Result)KM_ERROR_UNSUPPORTED_KEY_SIZE;
    }
    return TEE_SUCCESS;
}

static keymaster_error_t get_hmac_hashbits(const keymaster_key_param_set_t *params_hw_enforced, uint32_t *hash_bits)
{
    keymaster_digest_t digest = KM_DIGEST_NONE;
    bool check_fail = (params_hw_enforced == NULL || hash_bits == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (check_multi_tag_params(KM_TAG_DIGEST, params_hw_enforced) != 0) {
        tloge("check multi tag params failed\n");
        return (TEE_Result)KM_ERROR_UNSUPPORTED_DIGEST;
    }
    if (get_key_param(KM_TAG_DIGEST, &digest, params_hw_enforced) == -1) {
        tloge("get digest tag length from key failed\n");
        return (TEE_Result)KM_ERROR_UNSUPPORTED_DIGEST;
    }
    check_fail = (hash_mode_to_size_bits(digest, hash_bits) != KM_ERROR_OK || *hash_bits == 0);
    if (check_fail) {
        tloge("get hash bits filed\n");
        return (TEE_Result)KM_ERROR_UNSUPPORTED_DIGEST;
    }
    return KM_ERROR_OK;
}
TEE_Result check_hmac_key_params(keymaster_algorithm_t algorithm, const keymaster_key_param_set_t *params_hw_enforced)
{
    uint32_t min_tag_len = 0;
    uint32_t hash_size_bits = 0;
    if (algorithm != KM_ALGORITHM_HMAC)
        return TEE_SUCCESS;

    if (params_hw_enforced == NULL) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    keymaster_error_t km_ret = get_hmac_hashbits(params_hw_enforced, &hash_size_bits);
    if (km_ret != KM_ERROR_OK)
        return (TEE_Result)km_ret;

    int ret = get_key_param(KM_TAG_MIN_MAC_LENGTH, &min_tag_len, params_hw_enforced);
    if (ret == -1) {
        tloge("get gcm min tag length from key failed\n");
        return (TEE_Result)KM_ERROR_MISSING_MIN_MAC_LENGTH;
    }
    bool invalid_min_tag_len = ((min_tag_len < KM_MAC_MIN_TAG) || (min_tag_len % KM_BYTE_SIZE_8 != 0) ||
        (min_tag_len > hash_size_bits));
    if (invalid_min_tag_len) {
        tloge("min_tag_len %u is invalid\n", min_tag_len);
        return (TEE_Result)KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;
    }

    return TEE_SUCCESS;
}
TEE_Result check_gen_key_params(keymaster_algorithm_t algorithm, uint32_t key_size_bits,
    const keymaster_key_param_set_t *params_hw_enforced)
{
    if (params_hw_enforced == NULL) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret = check_key_size_bits(algorithm, key_size_bits, params_hw_enforced);
    if (ret != TEE_SUCCESS) {
        tloge("check key size failed\n");
        return ret;
    }
    ret = check_aes_tag(algorithm, params_hw_enforced);
    if (ret != TEE_SUCCESS) {
        tloge("check aes tags failed\n");
        return ret;
    }
    ret = check_hmac_key_params(algorithm, params_hw_enforced);
    if (ret != TEE_SUCCESS) {
        tloge("check hmac tags failed\n");
        return ret;
    }
    return TEE_SUCCESS;
}

keymaster_error_t check_aes_tag(keymaster_algorithm_t algorithm, const keymaster_key_param_set_t *params_hw_enforced)
{
    uint32_t block_mode  = 0;
    uint32_t min_tag_len = 0;
    bool condition = false;
    if (algorithm != KM_ALGORITHM_AES)
        return KM_ERROR_OK;
    if (params_hw_enforced == NULL) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (get_key_param(KM_TAG_BLOCK_MODE, &block_mode, params_hw_enforced) != 0) {
        tlogd("not specified block mod \n");
    } else {
        if (block_mode == KM_MODE_GCM) {
            if (get_key_param(KM_TAG_MIN_MAC_LENGTH, &min_tag_len, params_hw_enforced) != 0) {
                tloge("aes gcm mod generate key need specified mim mac len\n");
                return KM_ERROR_MISSING_MIN_MAC_LENGTH;
            }
            condition = ((min_tag_len % BITS_ONE_BYTE != 0 || min_tag_len > KM_AES_MAX_TAG) ||
                (min_tag_len < KM_AES_MIN_TAG));
            if (condition) {
                tloge("aes gcm mod unsupported mim mac len %u\n", min_tag_len);
                return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;
            }
        }
    }
    return KM_ERROR_OK;
}
