/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster crypto process use soft engine
 * Create: 2020-11-09
 */

#include "securec.h"
#include "keymaster_defs.h"
#include "km_tag_operation.h"
#include "keyblob.h"
#include "openssl/rsa.h"
#include "km_common.h"
#include "km_types.h"
#include "km_crypto_rsa.h"
#include "km_crypto_adaptor.h"
#include "km_key_adaptor.h"
static keymaster_error_t parse_input_for_soft_rsa_pkcs1_verify_digest_none(const rsa_pub_key_t *public_key,
    const uint8_t **msg_buf, uint32_t *parse_length)
{
    /* caller can ensure msg_buf is not null */
    bool check_fail = (public_key == NULL || msg_buf == NULL || parse_length == NULL || *msg_buf == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    const uint8_t *tmp = *msg_buf;
    /* caller can ensure public_key is not null */
    if (public_key->n_len < HEAD_NUM) {
        tloge("nlen is invalid");
        return KM_ERROR_INVALID_ARGUMENT;
    }
    uint32_t j = public_key->n_len - HEAD_NUM;
    uint32_t i = 0;

    for (; i < j; i++) {
        /* should decrypt to 0xff, caller can ensure tmp is not null */
        if (*tmp != 0xff) {
            if (*tmp == 0) {
                tmp++;
                *msg_buf = tmp;
                break;
            } else {
                return KM_ERROR_VERIFICATION_FAILED;
            }
        }
        tmp++;
        *msg_buf = tmp;
    }
    check_fail = ((i == j) || (i < MIN_MSG_LEN));
    if (check_fail) {
        tloge("i %u is should not equal to j %u, or i is less than 8\n", i, j);
        return KM_ERROR_VERIFICATION_FAILED;
    }
    i++;
    j -= i;
    *parse_length = j;
    return KM_ERROR_OK;
}

static keymaster_error_t check_valid_rsa_pkcs1_verify_digest_none(const uint8_t *msg_buf, const uint8_t *input_data,
                                                                  uint32_t input_data_len, uint32_t parse_length)
{
    if (parse_length > input_data_len) {
        tloge("parse_length %u is should not larger than input_data_len %u\n", parse_length, input_data_len);
        return KM_ERROR_VERIFICATION_FAILED;
    }
    int32_t tmp_ret = TEE_MemCompare(input_data, msg_buf, parse_length);
    if ((input_data == NULL) && (parse_length == 0)) {
        tlogd("Input data is NULL:verify success, input_data is NULL and j is 0\n");
        return KM_ERROR_OK;
    } else if (!tmp_ret) {
        tlogd("verify success\n");
        return KM_ERROR_OK;
    } else {
        tloge("verify failed temp2 is not equal to input, dump temp2 and input_data\n");
        return KM_ERROR_VERIFICATION_FAILED;
    }
}
static keymaster_error_t check_soft_rsa_pkcs1_verify_digest_none(const rsa_pub_key_t *public_key,
    const uint8_t *msg_buf, const uint8_t *input_data, uint32_t input_data_len)
{
    keymaster_error_t ret;
    uint32_t parse_length  = 0;
    const uint8_t *tmp           = msg_buf;
    const uint32_t index_0 = 0;
    const uint32_t index_1 = 1;
    bool check_fail = ((tmp[index_0] != index_0) || (tmp[index_1] != index_1));
    if (check_fail) {
        tloge("verify failed:temp2[0]=%u(should be 0), temp2[1]=%u(should be 1)\n", tmp[index_0], tmp[index_1]);
        return KM_ERROR_VERIFICATION_FAILED;
    }
    tmp++;
    tmp++;

    ret = parse_input_for_soft_rsa_pkcs1_verify_digest_none(public_key, &tmp, &parse_length);
    if (ret != KM_ERROR_OK) {
        tloge("parse input for soft rsa pkcs1 verify digest none failed\n");
        return ret;
    }
    return check_valid_rsa_pkcs1_verify_digest_none(tmp, input_data, input_data_len, parse_length);
}
/* do decrypt, then verify the output must be pkcs1 format then equal to input data */
static keymaster_error_t soft_rsa_pkcs1_verify_digest_none(rsa_pub_key_t *pub, uint8_t *input_data,
                                                           uint32_t input_data_len, uint8_t *signature,
                                                           uint32_t signature_len)
{
    if (pub == NULL) {
        tloge("public_key is null");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    keymaster_error_t ret = KM_ERROR_OK;
    uint8_t *temp         = NULL;
    uint32_t size_bytes   = pub->n_len;
    uint32_t tlen         = input_data_len;
    uint32_t flen         = size_bytes;
    int32_t result;
    /* 11 is RSA_PKCS1_PADDING_SIZE */
    if (tlen > flen - RSA_PKCS1_PADDING_SIZE) {
        tloge("tlen is erro,tlen %u,flen %u r\n", tlen, flen);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if ((size_bytes > sizeof(pub->n)) || (size_bytes == 0)) {
        tloge("size_bytes is error");
        return ret;
    }
    temp = (uint8_t *)TEE_Malloc(size_bytes, 0);
    if (temp == NULL) {
        tloge("temp malloc failed, alloc size is %u\n", size_bytes);
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    tlogd("signature_len is %u\n", signature_len);

    result = rsa_encrypt(temp, &size_bytes, signature, signature_len, pub, RSA_NO_PADDING, 0);
    if (result == 0) {
        ret = check_soft_rsa_pkcs1_verify_digest_none(pub, temp, input_data, input_data_len);
    } else {
        tloge("rsa_encrypt failed\n");
        ret = KM_ERROR_INVALID_ARGUMENT;
    }
    TEE_Free(temp);
    temp = NULL;
    return ret;
}

static keymaster_error_t none_padding_for_rsa_sign(key_auth *key_node, uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, uint32_t *signature_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    rsa_priv_key_t *priv = (rsa_priv_key_t *)key_node->key1;
    int32_t result;
    /* the calller can ensure priv is not null */
    uint32_t size_bytes = priv->n_len;

    if (digest_len > size_bytes) {
        tloge("when signature digest_len %u is larger than size_bytes %u\n", digest_len, size_bytes);
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }
    /* the calller can ensure signature_len is not null */
    result = rsa_decrypt(signature, signature_len, digest, digest_len, priv, RSA_NO_PADDING, 0);
    if (result != 0) {
        tloge("rsa_decrypt failed, ret %d\n", result);
        *signature_len = 0;
        /* for vts case, when message larger than modulus, must return KM_ERROR_INVALID_ARGUMENT */
        if (result == RSA_R_DATA_TOO_LARGE_FOR_MODULUS) {
            tloge("input digest has larger content than modulus\n");
            return KM_ERROR_INVALID_ARGUMENT;
        }
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return ret;
}

static keymaster_error_t none_padding_for_rsa_verify(key_auth *key_node, uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, uint32_t *signature_len)
{
    /* the calller can ensure key_node is not null */
    rsa_pub_key_t *pub = (rsa_pub_key_t *)key_node->key1;
    int32_t result;
    /* the calller can ensure pub is not null */
    uint32_t size_bytes = pub->n_len;
    /* *signature_len  is output param maybe 0 */
    if (digest_len > size_bytes) {
        tloge("when verify digest_len %u is larger than size_bytes %u\n", digest_len, size_bytes);
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }
    uint8_t *temp = (uint8_t *)TEE_Malloc(MAX_RSA_CRYPTO_DATA, 0);
    /* the calller can ensure signature_len is not null */
    if (temp == NULL) {
        tloge("temp malloc failed, alloc size is %u\n", *signature_len);
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    uint32_t out_len = MAX_RSA_CRYPTO_DATA;
    result           = rsa_encrypt(temp, &out_len, signature, *signature_len, pub, RSA_NO_PADDING, 0);
    if (result != 0) {
        tloge("rsa_encrypt failed\n");
        TEE_Free(temp);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if ((*signature_len < digest_len) ||
        (*signature_len > MAX_RSA_CRYPTO_DATA)) {
        tloge("signature_len check failed\n");
        TEE_Free(temp);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    uint8_t *temp2  = temp + (*signature_len - digest_len);
    int32_t tmp_ret = TEE_MemCompare(digest, temp2, digest_len);
    if (tmp_ret == 0) {
        TEE_Free(temp);
        return KM_ERROR_OK;
    } else {
        TEE_Free(temp);
        return KM_ERROR_VERIFICATION_FAILED;
    }
}

static keymaster_error_t oaep_pad_for_rsa_enc(key_auth *key_node, uint8_t *src_data, uint32_t src_len,
    uint8_t *dest_data, uint32_t *dest_len, int force)
{
    keymaster_error_t ret = KM_ERROR_OK;
    int result;
    /* the caller can ensure the key_node is not null */
    rsa_pub_key_t *pub        = (rsa_pub_key_t *)key_node->key1; /* rsa soft key include the pub key at head */
    keymaster_digest_t digest = key_node->digest;
    uint32_t digest_len       = 64;
    uint32_t hash_nid         = 0;

    if (km_hash_to_soft_hash(digest, &hash_nid)) {
        tloge("km_hash_to_soft_hash failed\n");
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    tlogd("hash_nid is %u\n", hash_nid);

    if (get_real_hash_len(digest, &digest_len)) {
        tloge("digest_mode %d\n", digest);
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }

    /* The buffer must be at least modulus size bytes long */
    if (force == 0)
        /* the caller can ensure the dest_len is not null */
        if (*dest_len < pub->n_len) {
            tloge("The buffer must be at least modulus size bytes long\n");
            return KM_ERROR_OUTPUT_PARAMETER_NULL;
        }

    /* if src is null soft return fail but DX does not, so we generate inner buffer */
    if ((src_data == NULL) || (src_len == 0)) {
        uint8_t *temp = NULL;
        if (pub->n_len < BASE_NUM_TWO * digest_len + BASE_NUM_TWO) {
            tloge("pub->n_len check failed, pub->n_len %u\n", pub->n_len);
            return KM_ERROR_UNKNOWN_ERROR;
        }
        uint32_t temp_size = pub->n_len - BASE_NUM_TWO * digest_len - BASE_NUM_TWO;
        temp = (uint8_t *)TEE_Malloc(temp_size, 0);
        if (temp == NULL) {
            tloge("temp malloc failed, size %u\n", temp_size);
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        *(uint32_t *)temp = RSA_4096_CTS_HELP;
        result = rsa_encrypt(dest_data, dest_len, temp, temp_size, pub, RSA_PKCS1_OAEP_PADDING, hash_nid);
        TEE_Free(temp);
    } else {
        result = rsa_encrypt(dest_data, dest_len, src_data, src_len, pub, RSA_PKCS1_OAEP_PADDING, hash_nid);
    }
    if (result != 0) {
        tloge("rsa_encrypt failed, *dest_len = %u\n", *dest_len);
        *dest_len = 0;
        ret = KM_ERROR_UNKNOWN_ERROR;
    }

    return ret;
}

static keymaster_error_t oaep_pad_for_rsa_dec(key_auth *key_node, uint8_t *src_data, uint32_t src_len,
    uint8_t *dest_data, uint32_t *dest_len, int force)
{
    keymaster_error_t ret = KM_ERROR_OK;
    int result;
    /* the caller can ensure the key_node is not null */
    rsa_priv_key_t *priv      = (rsa_priv_key_t *)key_node->key1;
    keymaster_digest_t digest = key_node->digest;
    uint32_t digest_len       = 64;
    uint32_t hash_nid         = 0;

    if (km_hash_to_soft_hash(digest, &hash_nid)) {
        tloge("km_hash_to_soft_hash failed\n");
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    tlogd("hash_nid is %u\n", hash_nid);

    if (get_real_hash_len(digest, &digest_len)) {
        tloge("digest_mode %d\n", digest);
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    tlogd("digest_len is %u\n", digest_len);

    if (force == 0)
        /* the caller can ensure the dest_len is not null */
        if (*dest_len < ((uint16_t)(priv->n_len - (BASE_NUM_TWO * digest_len) - BASE_NUM_TWO))) {
            tloge("OutputSize must >= (modulus size - 2*HashLen - 2)\n");
            return KM_ERROR_OUTPUT_PARAMETER_NULL;
        }
    result = rsa_decrypt(dest_data, dest_len, src_data, src_len, priv, RSA_PKCS1_OAEP_PADDING, hash_nid);
    /* add for VTS error case */
    if ((result != 0) || (*dest_len == KEY_BLOB_MAX_SIZE)) {
        tloge("rsa_oaep_decrypt failed,result = %d\n", result);
        *dest_data = 0;
        ret = KM_ERROR_UNKNOWN_ERROR;
    }
    /* here we use need check if output have magic */
    if (*(uint32_t *)dest_data == RSA_4096_CTS_HELP)
        *dest_len = 0;

    return ret;
}

keymaster_error_t oaep_pad_for_rsa_enc_dec(key_auth *key_node, keymaster_purpose_t purpose, uint8_t *src_data,
                                           uint32_t src_len, uint8_t *dest_data, uint32_t *dest_len, int force)
{
    keymaster_error_t ret = KM_ERROR_UNSUPPORTED_PURPOSE;

    if (purpose == KM_PURPOSE_ENCRYPT)
        ret = oaep_pad_for_rsa_enc(key_node, src_data, src_len, dest_data, dest_len, force);
    else if (purpose == KM_PURPOSE_DECRYPT)
        ret = oaep_pad_for_rsa_dec(key_node, src_data, src_len, dest_data, dest_len, force);

    return ret;
}

static keymaster_error_t check_rsa_len(uint32_t size_bytes, uint32_t input_data_len, uint32_t *signature_len)
{
    if (size_bytes > KEY_SIZE_512) {
        tloge("max keysize is 4096\n");
        return KM_ERROR_UNSUPPORTED_KEY_SIZE;
    }
    if (signature_len == NULL) {
        tloge("signature_len is null");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (input_data_len > (size_bytes - RSA_PKCS1_PADDING_SIZE))
        return KM_ERROR_UNKNOWN_ERROR;
    return KM_ERROR_OK;
}
static keymaster_error_t soft_rsa_pkcs1_sign_digest_none(rsa_priv_key_t *priv, const uint8_t *input_data,
                                                         uint32_t input_data_len, uint8_t *signature,
                                                         uint32_t *signature_len)
{
    if (priv == NULL) {
        tloge("priv is null");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    keymaster_error_t ret;
    uint32_t size_bytes;
    size_bytes        = priv->n_len;
    uint8_t *temp_buf = NULL;
    int32_t result;
    ret = check_rsa_len(size_bytes, input_data_len, signature_len);
    if (ret != KM_ERROR_OK)
        return ret;
    temp_buf = TEE_Malloc(size_bytes, 0);
    if (temp_buf == NULL) {
        tloge("failed to allocate size_bytes %u buffer\n", size_bytes);
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    ret = pack_input_data_to_pkcs1_format(input_data_len, (uint32_t)size_bytes, input_data, temp_buf);
    if (ret != KM_ERROR_OK) {
        tloge("pack_input_data_to_pkcs1_format failed\n");
        goto exit;
    }
    result = rsa_decrypt(signature, signature_len, temp_buf, size_bytes, priv, RSA_NO_PADDING, 0);
    if (result != 0) {
        tloge("rsa_decrypt failed\n");
        if (signature_len != NULL)
            *signature_len = 0;
        if (result == RSA_R_DATA_TOO_LARGE_FOR_MODULUS) {
            tloge("input digest has larger content than modulus\n");
            ret = KM_ERROR_INVALID_ARGUMENT;
        }
        ret = KM_ERROR_UNKNOWN_ERROR;
    } else {
        *signature_len = size_bytes;
        ret            = KM_ERROR_OK;
    }
exit:
    TEE_Free(temp_buf);
    temp_buf = NULL;
    return ret;
}
static keymaster_error_t pkcs_padding_for_rsa_sign(key_auth *key_node, uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, uint32_t *signature_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    /* the calller can ensure key_node is not null */
    int32_t digest_mode      = key_node->digest;
    rsa_priv_key_t *priv = (rsa_priv_key_t *)key_node->key1;
    int32_t result           = 0;
    uint32_t hash_nid    = 0;

    int32_t tmp_ret = km_hash_to_soft_hash((keymaster_digest_t)digest_mode, &hash_nid);
    if (tmp_ret != 0) {
        tloge("km hash to soft hash failed\n");
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }

    if (digest_mode == KM_DIGEST_NONE) {
        /* the calller can ensure signature_len is not null */
        ret = soft_rsa_pkcs1_sign_digest_none(priv, digest, digest_len, signature, signature_len);
        if (ret != KM_ERROR_OK) {
            tloge("soft_RSA_PKCS1_Sign_digest_none failed, ret 0x%x\n", ret);
            result = -1;
        }
    } else {
        result = rsa_sign_digest(signature, signature_len, digest, digest_len, priv, 0, hash_nid, RSA_PKCS1_PADDING);
    }
    if (result != 0) {
        tloge("rsa_sign_digest failed\n");
        *signature_len = 0;
        ret            = KM_ERROR_UNKNOWN_ERROR;
    }
    return ret;
}

static keymaster_error_t pkcs_padding_for_rsa_verify(key_auth *key_node, uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, const uint32_t *signature_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    /* the calller can ensure key_node is not null */
    int32_t digest_mode    = key_node->digest;
    rsa_pub_key_t *pub = (rsa_pub_key_t *)key_node->key1;
    uint32_t hash_nid  = 0;

    int32_t tmp_ret = km_hash_to_soft_hash((keymaster_digest_t)digest_mode, &hash_nid);
    if (tmp_ret != 0) {
        tloge("km_hash_to_soft_hash failed\n");
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }

    if (digest_mode == KM_DIGEST_NONE) {
        ret = soft_rsa_pkcs1_verify_digest_none(pub, digest, digest_len, signature, *signature_len);
        if (ret != KM_ERROR_OK && ret != KM_ERROR_UNKNOWN_ERROR) {
            tloge("soft_RSA_PKCS1_Verify_digest_none failed, ret 0x%x\n", ret);
            ret = KM_ERROR_VERIFICATION_FAILED;
        }
    } else {
        tmp_ret = rsa_verify_digest(signature, *signature_len, digest, digest_len, pub, 0, hash_nid, RSA_PKCS1_PADDING);
        if (tmp_ret != 0) {
            tloge("rsa_verify_digest failed\n");
            ret = KM_ERROR_VERIFICATION_FAILED;
        }
    }

    return ret;
}
static keymaster_error_t pkcs_padding_for_rsa_sign_verify(key_auth *key_node, keymaster_purpose_t purpose,
                                                          uint8_t *digest, uint32_t digest_len, uint8_t *signature,
                                                          uint32_t *signature_len)
{
    keymaster_error_t ret = KM_ERROR_UNSUPPORTED_PURPOSE;

    if (purpose == KM_PURPOSE_SIGN)
        ret = pkcs_padding_for_rsa_sign(key_node, digest, digest_len, signature, signature_len);
    else if (purpose == KM_PURPOSE_VERIFY)
        ret = pkcs_padding_for_rsa_verify(key_node, digest, digest_len, signature, signature_len);
    return ret;
}

static keymaster_error_t pss_padding_for_rsa_sign(key_auth *key_node, uint8_t *digest, uint32_t digest_len,
                                                  uint8_t *signature, uint32_t *signature_len)
{
    /* the calller can ensure key_node is not null */
    int32_t digest_mode = key_node->digest;
    rsa_priv_key_t *priv = (rsa_priv_key_t *)key_node->key1;
    int32_t result;
    uint32_t hash_nid = 0;
    uint16_t salt_len = 0;
    /* the calller can ensure priv is not null */
    uint32_t size_bytes = priv->n_len;

    if (km_hash_to_soft_hash((keymaster_digest_t)digest_mode, &hash_nid) != 0) {
        tloge("km_hash_to_soft_hash failed\n");
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    if ((int32_t)get_saltlen_for_cc(size_bytes, digest_mode, &salt_len) != 0) {
        tloge("failed to get saltlen when sign\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    tlogd("when sign salt_len is %u\n", salt_len);
    result =
        rsa_sign_digest(signature, signature_len, digest, digest_len, priv, salt_len, hash_nid, RSA_PKCS1_PSS_PADDING);
    if (result != 0) {
        tloge("rsa_sign_digest failed\n");
        *signature_len = 0;
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t pss_padding_for_rsa_verify(key_auth *key_node, uint8_t *digest, uint32_t digest_len,
                                                    uint8_t *signature, const uint32_t *signature_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    /* the calller can ensure key_node is not null */
    int32_t digest_mode = key_node->digest;
    rsa_pub_key_t *pub = (rsa_pub_key_t *)key_node->key1;
    uint32_t hash_nid  = 0;
    uint16_t salt_len  = 0;
    /* the calller can ensure pub is not null */
    uint32_t size_bytes = pub->n_len;

    int32_t tmp_ret = km_hash_to_soft_hash((keymaster_digest_t)digest_mode, &hash_nid);
    if (tmp_ret != 0) {
        tloge("km hash to soft hash failed\n");
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    tmp_ret = (int)get_saltlen_for_cc(size_bytes, digest_mode, &salt_len);
    if (tmp_ret != 0) {
        tloge("failed to get saltlen when verify\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    tlogd("when verify saltlen is %u\n", salt_len);
    tmp_ret = rsa_verify_digest(signature, *signature_len, digest, digest_len, pub, salt_len, hash_nid,
                                RSA_PKCS1_PSS_PADDING);
    if (tmp_ret != 0) {
        tloge("rsa_verify_digest failed\n");
        ret = KM_ERROR_VERIFICATION_FAILED;
    }

    return ret;
}
static keymaster_error_t pss_padding_for_rsa_sign_verify(key_auth *key_node, keymaster_purpose_t purpose,
                                                         uint8_t *digest, uint32_t digest_len, uint8_t *signature,
                                                         uint32_t *signature_len)
{
    keymaster_error_t ret = KM_ERROR_UNSUPPORTED_PURPOSE;

    if (purpose == KM_PURPOSE_SIGN)
        ret = pss_padding_for_rsa_sign(key_node, digest, digest_len, signature, signature_len);
    else if (purpose == KM_PURPOSE_VERIFY)
        ret = pss_padding_for_rsa_verify(key_node, digest, digest_len, signature, signature_len);
    return ret;
}

static keymaster_error_t none_padding_for_rsa_sign_verify(key_auth *key_node, keymaster_purpose_t purpose,
                                                          uint8_t *digest, uint32_t digest_len, uint8_t *signature,
                                                          uint32_t *signature_len)
{
    keymaster_error_t ret;

    if (purpose == KM_PURPOSE_SIGN)
        ret = none_padding_for_rsa_sign(key_node, digest, digest_len, signature, signature_len);
    else if (purpose == KM_PURPOSE_VERIFY)
        ret = none_padding_for_rsa_verify(key_node, digest, digest_len, signature, signature_len);
    else
        ret = KM_ERROR_UNSUPPORTED_PURPOSE;

    if (ret != KM_ERROR_OK) {
        tloge("none_padding_for_rsa_sign_verify error: cc_ret is 0x%x\n", ret);
        if (purpose == KM_PURPOSE_SIGN && ret == KM_ERROR_INVALID_ARGUMENT)
            return ret;
        ret = KM_ERROR_VERIFICATION_FAILED;
    }

    return ret;
}
static keymaster_error_t proc_all_padding_for_soft_rsa_sign_verify(key_auth *key_node, keymaster_purpose_t purpose,
    uint8_t *digest, uint32_t digest_len, uint8_t *signature, uint32_t *signature_len)
{
    keymaster_error_t ret = KM_ERROR_UNSUPPORTED_PADDING_MODE;
    if (key_node == NULL) {
        tloge("key_node is null");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }

    if (key_node->padding == KM_PAD_RSA_PKCS1_1_5_SIGN)
        ret = pkcs_padding_for_rsa_sign_verify(key_node, purpose, digest, digest_len, signature, signature_len);
    else if (key_node->padding == KM_PAD_RSA_PSS)
        ret = pss_padding_for_rsa_sign_verify(key_node, purpose, digest, digest_len, signature, signature_len);
    else if (key_node->padding == KM_PAD_NONE)
        ret = none_padding_for_rsa_sign_verify(key_node, purpose, digest, digest_len, signature, signature_len);
    return ret;
}

keymaster_error_t soft_rsa_sign_verify(key_auth *key_node, keymaster_purpose_t purpose, uint8_t *digest,
                                       uint32_t digest_len, uint8_t *signature, uint32_t *signature_len)
{
    keymaster_error_t ret;
    uint32_t digest_lenth = digest_len;
    bool check_fail = (signature_len == NULL || key_node == NULL || key_node->key1 == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (key_node->key1_size != sizeof(rsa_priv_key_t)) {
        tloge("key size error\n");
        return KM_ERROR_INVALID_ARGUMENT;
    }
    tlogd("digest_len is %u\n", digest_lenth);
    tlogd("padding is 0x%x, purpose is 0x%x, digest_mode is 0x%x\n", key_node->padding, purpose, key_node->digest);

    ret = preproc_for_rsa_sign_verify(((rsa_pub_key_t *)key_node->key1)->n_len, purpose,
                                      key_node->padding, key_node->digest, &digest_lenth);
    if (ret != KM_ERROR_OK) {
        tloge("preproc for rsa sign verify failed\n");
        return ret;
    }
    ret = proc_all_padding_for_soft_rsa_sign_verify(key_node, purpose, digest, digest_lenth, signature, signature_len);
    if (ret != KM_ERROR_OK) {
        tloge("proc RSA_sign_verify failed, padding 0x%x, purpose 0x%x, ret 0x%x\n", key_node->padding, purpose, ret);
        return ret;
    }
    return ret;
}

bool use_soft_engine(const key_auth *key_node)
{
    /* GP doesn't support padding with OAEP and digest with MD5 */
    bool rsa_use_soft_check = (key_node->algorithm == KM_ALGORITHM_RSA &&
        (((key_node->purpose == KM_PURPOSE_ENCRYPT || key_node->purpose == KM_PURPOSE_DECRYPT) &&
        (key_node->padding == KM_PAD_RSA_OAEP && key_node->digest == KM_DIGEST_MD5)) ||
        ((key_node->purpose == KM_PURPOSE_SIGN || key_node->purpose == KM_PURPOSE_VERIFY) &&
        (key_node->padding == KM_PAD_NONE || key_node->digest == KM_DIGEST_NONE))));
    bool ecc_use_soft_check = ((key_node->algorithm == KM_ALGORITHM_EC) &&
        (key_node->digest == KM_DIGEST_MD5 || key_node->digest == KM_DIGEST_NONE));
    bool use_soft = (rsa_use_soft_check || ecc_use_soft_check);
    tlogd("use soft %u\n", use_soft);
    return use_soft;
}

uint32_t soft_rsa_begin(TEE_ObjectHandle key, key_auth *key_node)
{
    TEE_Result ret;
    key_node->use_soft = true;
    rsa_priv_key_t *rsa_priv_key = (rsa_priv_key_t *)TEE_Malloc(sizeof(rsa_priv_key_t), 0);
    if (rsa_priv_key == NULL) {
        tloge("soft rsa begin malloc fail");
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    ret = covert_rsa_prvkey_gp2sw(key, rsa_priv_key);
    if (ret != TEE_SUCCESS) {
        tloge("soft rsa begin convert rsa key fail");
        (void)memset_s(rsa_priv_key, sizeof(*rsa_priv_key), 0x0, sizeof(*rsa_priv_key));
        TEE_Free(rsa_priv_key);
        return ret;
    }
    if (key_node->key1 != NULL) {
        (void)memset_s(key_node->key1, key_node->key1_size, 0x0, key_node->key1_size);
        TEE_Free(key_node->key1);
        key_node->key1 = NULL;
        key_node->key1_size = 0;
    }
    key_node->key1 = (uint8_t *)rsa_priv_key;
    key_node->key1_size = sizeof(rsa_priv_key_t);
    return ret;
}

keymaster_error_t proc_digest_none_or_md5_for_ec_sign(key_auth *key_node, uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, uint32_t *signature_len)
{
    int sw_ret;
    ecc_priv_key_t *sw_priv_key = NULL;
    uint32_t out_sig_len = *signature_len;
    bool check_digest = (((digest == NULL) || (digest_len == 0)) && (key_node->digest == KM_DIGEST_NONE));
    if (check_digest)
        tlogd("empty digest none message for ec sign\n");

    sw_priv_key = (ecc_priv_key_t *)key_node->key1;
    sw_ret = ecc_sign_digest(signature, out_sig_len, digest, digest_len, sw_priv_key);
    if ((sw_ret < 0) || (sw_ret > (int)*signature_len)) {
        tloge("ecc_sign_digest error:%d/%u\n", sw_ret, *signature_len);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if (memset_s(sw_priv_key, sizeof(ecc_priv_key_t), 0, sizeof(ecc_priv_key_t))) {
        tloge("memset_s sw_priv_key failed\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    *signature_len = sw_ret;
    tlogd("ec sign success,signature_len=%u\n", *signature_len);
    return KM_ERROR_OK;
}

keymaster_error_t proc_digest_none_or_md5_for_ec_verify(key_auth *key_node, uint8_t *digest, uint32_t digest_len,
    uint8_t *signature, const uint32_t *signature_len)
{
    int sw_ret;
    ecc_pub_key_t *sw_pub_key = NULL;
    bool condition_check = ((signature == NULL) || (*signature_len == 0));
    if (condition_check) {
        tloge("empty signature message for ec verify\n");
        return KM_ERROR_VERIFICATION_FAILED;
    }
    condition_check = (((digest == NULL) || (digest_len == 0)) && (key_node->digest == KM_DIGEST_NONE));
    if (condition_check)
        tlogd("empty digest none message for ec verify\n");

    sw_pub_key = (ecc_pub_key_t *)key_node->key2;
    sw_ret = ecc_verify_digest(signature, *signature_len, digest, digest_len, sw_pub_key);
    if (sw_ret != 1) {
        tloge("ecc_verify_digest error.\n");
        return KM_ERROR_VERIFICATION_FAILED;
    }
    tlogd("ec verify success\n");
    return KM_ERROR_OK;
}
