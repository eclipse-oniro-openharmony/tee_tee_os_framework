/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster ecdsa cipher functions implementation
 * Create: 2020-11-09
 */

#include "securec.h"
#include "keymaster_defs.h"
#include "km_crypto.h"
#include "km_tag_operation.h"
#include "keyblob.h"
#include "km_types.h"
#include "km_common.h"
#include "km_crypto_adaptor.h"
#include "km_crypto_sw_engine.h"
#include "km_crypto_check.h"
#include "km_key_adaptor.h"
int32_t ec_sig_asn1_format(uint8_t *in, uint32_t *in_len, uint32_t in_buf_len)
{
    bool check_fail = ((in == NULL) || (in_len == NULL));
    if (check_fail) {
        tloge("invalid input params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (*in_len < KM_NUM_TWO) {
        tloge("invalid in_len!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t *ptr    = NULL;
    uint8_t *ptr_in = NULL;
    errno_t rc;
    uint8_t buf[SIG_MAX_LEN] = { 0 };
    uint32_t buf_len         = SIG_MAX_LEN;

    uint32_t integer_len = *in_len / KM_NUM_TWO;
    rc                   = memcpy_s(buf, SIG_MAX_LEN, in, *in_len);
    if (rc != EOK) {
        tloge("[error]memcpy_s failed, rc=%d, line:%d\n", rc, __LINE__);
        return -1;
    }

    ptr    = buf;
    ptr_in = in;
    /* write first integer */
    insert_tlv(KM_ASN1_INT, integer_len, in, &ptr, &buf_len);
    /* write second integer */
    insert_tlv(KM_ASN1_INT, *in_len - integer_len, in + integer_len, &ptr, &buf_len);
    /* Write integers into sequence */
    insert_tlv(KM_ASN1_SEQ, (uint32_t)(ptr - buf), buf, &ptr_in, &in_buf_len);

    *in_len = (uint32_t)(ptr_in - in);

    return 0;
}

static keymaster_error_t proc_ec_sign(key_auth *key_node, uint8_t *digest, uint32_t digest_len,
                                      uint8_t *signature, uint32_t *signature_len)
{
    TEE_Result result;
    uint32_t orig_sig_len = *signature_len;
    size_t sig_len = *signature_len;
    size_t dig_len = digest_len;
    TEE_OperationHandle ec_operation = (TEE_OperationHandle)key_node->crypto_ctxt;
    if (key_node->digest == KM_DIGEST_MD5 || key_node->digest == KM_DIGEST_NONE) {
        bool check_fail = (key_node->key1 == NULL || key_node->key1_size != sizeof(ecc_priv_key_t));
        if (check_fail) {
            tloge("key is null\n");
            return KM_ERROR_UNEXPECTED_NULL_POINTER;
        }
        return proc_digest_none_or_md5_for_ec_sign(key_node, digest, digest_len, signature, signature_len);
    } else {
        if (ec_operation == NULL) {
            tloge("TEE_OperationHandle is NULL\n");
            return KM_ERROR_UNEXPECTED_NULL_POINTER;
        }
        result = TEE_AsymmetricSignDigest(ec_operation, NULL, 0, digest, dig_len, signature, &sig_len);
        if (result != TEE_SUCCESS) {
            tloge("asymmetric sign digest failed\n");
            return KM_ERROR_UNKNOWN_ERROR;
        }
        *signature_len = sig_len;
        result = (TEE_Result)ec_sig_asn1_format(signature, signature_len, orig_sig_len);
        if (result) {
            tloge("ec sig asn1 format error\n");
            return (keymaster_error_t)result;
        }
        tlogd("asymmetric sign digest success, sig_len is %u\n", *signature_len);
    }
    tlogd("ec sign verify success\n");
    return KM_ERROR_OK;
}

static int32_t do_asn1_seq(uint8_t **buf_end, uint32_t *buf_len, int32_t *len)
{
    bool check_fail = (len == NULL || buf_end == NULL || *buf_end == NULL || buf_len == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return -1;
    }
    uint32_t type;
    uint32_t hlen;
    /* ASN.1 SEQUENCE */
    *len = get_next_tlv(&type, &hlen, *buf_end, *buf_len);
    if ((*len < 0) || (type != KM_ASN1_SEQ)) {
        tloge("sig extract sequence header error,type=0x%x\n", type);
        return -1;
    }
    check_fail = ((UINT32_MAX - hlen) < (uint32_t)*len || (hlen + (uint32_t)*len) > *buf_len);
    if (check_fail) {
        tloge("integer bound check failed\n");
        return -1;
    }
    *buf_end += hlen;
    *buf_len -= hlen;
    return 0;
}

static int32_t do_asn1_interger(int32_t *len, uint32_t *buf_len, uint8_t **buf_end, keymaster_blob_t *in_end,
    uint32_t mod_len, uint8_t *in, uint32_t *in_len)
{
    errno_t rc;
    uint32_t type = KM_ASN1_NULL;
    uint32_t hlen;
    *len = get_next_tlv(&type, &hlen, *buf_end, *buf_len);
    bool check_fail = ((*len < 0) || (type != KM_ASN1_INT));
    if (check_fail) {
        tloge("sig extract first interger error,type=0x%x\n", type);
        return -1;
    }
    check_fail = (((UINT32_MAX - hlen) < (uint32_t)*len) || ((hlen + (uint32_t)*len) > *buf_len));
    if (check_fail) {
        tloge("invalid first interger length,hlen/len/buf_len = %u/%d/%u\n", hlen, *len, *buf_len);
        return -1;
    }
    *buf_end += hlen;
    *buf_len -= hlen;

    rc = memset_s(in, *in_len, 0, *in_len);
    if (rc != EOK) {
        tloge("[error]memset_s failed, rc=%d, line:%d\n", rc, __LINE__);
        return -1;
    }

    *in_len = mod_len;
    tlogd("mod_len=%u and len=%d\n", mod_len, *len);
    if ((uint32_t)*len > mod_len)
        rc = memcpy_s(in_end->data_addr, in_end->data_length, *buf_end + ((uint32_t)*len - mod_len), mod_len);
    else
        rc = memcpy_s(in_end->data_addr + (mod_len - (uint32_t)*len), in_end->data_length - (mod_len - (uint32_t)*len),
            *buf_end, (uint32_t)*len);
    if (rc != EOK) {
        tloge("[error]memcpy_s failed, rc=%d, line:%d\n", rc, __LINE__);
        return -1;
    }
    *buf_end += *len;
    *buf_len -= (uint32_t)*len;
    in_end->data_addr += mod_len;
    in_end->data_length -= mod_len;
    return 0;
}
static int32_t do_asn1_integer_2nd(uint8_t **buf_end, uint32_t buf_len, int32_t *len)
{
    bool check_fail = (len == NULL || buf_end == NULL || *buf_end == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return -1;
    }
    uint32_t type = KM_ASN1_NULL;
    uint32_t hlen;
    *len = get_next_tlv(&type, &hlen, *buf_end, buf_len);
    check_fail = ((*len < 0) || (type != KM_ASN1_INT));
    if (check_fail) {
        tloge("sig extract second interger error, type=0x%x\n", type);
        return -1;
    }
    check_fail = ((UINT32_MAX - hlen) < (uint32_t)*len || (hlen + (uint32_t)*len) > buf_len);
    if (check_fail) {
        tloge("integer bound check failed\n");
        return -1;
    }
    *buf_end += hlen;
    return 0;
}
int32_t ec_sig_gp_format(uint8_t *in, uint32_t *in_len, uint32_t key_size_in_bits)
{
    bool check_fail = ((in == NULL) || (in_len == NULL) || *in_len < KM_NUM_NINE);
    if (check_fail) {
        tloge("invalid input params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t len;
    keymaster_blob_t buf = { NULL, *in_len };
    buf.data_addr = (uint8_t *)TEE_Malloc(buf.data_length, TEE_MALLOC_FILL_ZERO);
    if (buf.data_addr == NULL) {
        tloge("mem alloc failed\n");
        return -1;
    }
    uint8_t *buf_end = buf.data_addr;
    keymaster_blob_t in_blob = { in, *in_len };
    uint32_t mod_len = (key_size_in_bits + KM_NUM_SEVEN) >> KM_NUM_THREE;

    errno_t rc = memcpy_s(buf.data_addr, buf.data_length, in, *in_len);
    if (rc != EOK)
        goto free_buf;

    /* ASN.1 SEQUENCE */
    if (do_asn1_seq(&buf_end, &buf.data_length, &len) != 0)
        goto free_buf;
    /* ASN.1 INTERGER */
    if (do_asn1_interger(&len, &buf.data_length, &buf_end, &in_blob, mod_len, in, in_len) != 0)
        goto free_buf;

    /* ASN.1 INTERGER */
    if (do_asn1_integer_2nd(&buf_end, buf.data_length, &len) != 0)
        goto free_buf;

    *in_len += mod_len;
    if ((uint32_t)len > mod_len)
        rc = memcpy_s(in_blob.data_addr, in_blob.data_length, buf_end + ((uint32_t)len - mod_len), mod_len);
    else
        rc = memcpy_s(in_blob.data_addr + (mod_len - (uint32_t)len), in_blob.data_length - (mod_len - (uint32_t)len),
            buf_end, (uint32_t)len);
    if (rc != EOK)
        goto free_buf;

    free_blob(&buf);
    return 0;
free_buf:
    free_blob(&buf);
    return -1;
}
static keymaster_error_t proc_ec_verify(key_auth *key_node, uint8_t *digest, uint32_t digest_len,
                                        uint8_t *signature, uint32_t *signature_len)
{
    TEE_Result result;
    size_t dig_len = digest_len;
    TEE_OperationHandle ec_operation = (TEE_OperationHandle)key_node->crypto_ctxt;
    if (key_node->digest == KM_DIGEST_MD5 || key_node->digest == KM_DIGEST_NONE) {
        bool check_fail = (key_node->key2 == NULL || key_node->key2_size != sizeof(ecc_pub_key_t));
        if (check_fail) {
            tloge("key is null\n");
            return KM_ERROR_UNEXPECTED_NULL_POINTER;
        }
        return proc_digest_none_or_md5_for_ec_verify(key_node, digest, digest_len, signature, signature_len);
    } else {
        if (ec_operation == NULL) {
            tloge("TEE_OperationHandle is NULL\n");
            return KM_ERROR_UNEXPECTED_NULL_POINTER;
        }
        if ((signature == NULL) || (*signature_len == 0)) {
            tloge("signature input is null\n");
            return KM_ERROR_VERIFICATION_FAILED;
        }
        uint32_t key_size_in_bits = key_node->key1_size;
        if (key_size_in_bits == 0) {
            tloge("key_size is invalid\n");
            return KM_ERROR_VERIFICATION_FAILED;
        }
        if (ec_sig_gp_format(signature, signature_len, key_size_in_bits) != 0) {
            tloge("ec sig dx format error\n");
            return KM_ERROR_VERIFICATION_FAILED;
        }
        size_t sig_len = *signature_len;
        result = TEE_AsymmetricVerifyDigest(ec_operation, NULL, 0, digest, dig_len, signature, sig_len);
        if (result != TEE_SUCCESS) {
            tloge("asymmetric verify digest failed\n");
            return KM_ERROR_VERIFICATION_FAILED;
        }
        tlogd("asymmetric verify digest success\n");
    }
    tlogd("ec sign verify success\n");
    return KM_ERROR_OK;
}

keymaster_error_t ec_sign_verify(key_auth *key_node, keymaster_purpose_t purpose, uint8_t *digest, uint32_t digest_len,
                                 uint8_t *signature, uint32_t *signature_len)
{
    if (signature_len == NULL) {
        tloge("signature_len is null, may km_abort call\n");
        return KM_ERROR_OK;
    }
    if (key_node == NULL) {
        tloge("key_node is null.\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    tlogd("signature_len is %u and digest_len=%u\n", *signature_len, digest_len);
    if (purpose == KM_PURPOSE_SIGN) {
        return proc_ec_sign(key_node, digest, digest_len, signature, signature_len);
    } else if (purpose == KM_PURPOSE_VERIFY) {
        return proc_ec_verify(key_node, digest, digest_len, signature, signature_len);
    } else {
        tloge("invalid purpose %d\n", purpose);
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }
}

static keymaster_error_t operation_ec_init_obj(struct keymaterial_ecdsa_header *ec_header,
    TEE_ObjectHandle *ec_objecthandle, const uint32_t version, const struct kb_crypto_factors *factors)
{
    bool check_fail = (ec_header == NULL || ec_objecthandle == NULL || factors == NULL);
    if (check_fail) {
        tloge("null pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    uint8_t temp_buf[MAX_KEY_BUFFER_LEN] = { 0 };
    keymaster_blob_t encrypted_key = { ec_header->key, ec_header->key_buff_len };
    keymaster_blob_t decrypted_key = { temp_buf, ec_header->key_buff_len };
    struct keyblob_crypto_ctx ctx = {
        version, (uint32_t)TEE_MODE_DECRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { ec_header->iv, IV_LEN },
        *factors
    };
    if (keyblob_crypto(&encrypted_key, &decrypted_key, &ctx) != TEE_SUCCESS) {
        tloge("keyblob crypto operation failed.\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }

    if (init_key_obj(KM_ALGORITHM_EC, KM_DIGEST_NONE, MAX_ECDSA_KEYPAIR_SIZE, ec_objecthandle, &decrypted_key) !=
        TEE_SUCCESS) {
        tloge("failed to allocate and init key object\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    (*ec_objecthandle)->ObjectInfo->objectUsage |= TEE_USAGE_EXTRACTABLE;
    if (TEE_RestrictObjectUsage1(*ec_objecthandle, (*ec_objecthandle)->ObjectInfo->objectUsage) != TEE_SUCCESS) {
        tloge("set object handle extractable usage failed\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t soft_ec_begin(key_auth * const key_node, TEE_ObjectHandle ec_objecthandle)
{
    TEE_Result ret;
    ecc_priv_key_t *ecc_priv_key = TEE_Malloc(sizeof(*ecc_priv_key), 0);
    if (ecc_priv_key == NULL) {
        tloge("malloc failed");
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    ret = covert_ec_prvkey_gp2sw(ec_objecthandle, ecc_priv_key);
    if (ret != TEE_SUCCESS) {
        (void)memset_s(ecc_priv_key, sizeof(*ecc_priv_key), 0x0, sizeof(*ecc_priv_key));
        TEE_Free(ecc_priv_key);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    ecc_pub_key_t *ecc_pub_key = TEE_Malloc(sizeof(*ecc_pub_key), 0);
    if (ecc_pub_key == NULL) {
        tloge("malloc failed");
        (void)memset_s(ecc_priv_key, sizeof(*ecc_priv_key), 0x0, sizeof(*ecc_priv_key));
        TEE_Free(ecc_priv_key);
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    ret = covert_ec_pubkey_gp2sw(ec_objecthandle, ecc_pub_key);
    if (ret != TEE_SUCCESS) {
        (void)memset_s(ecc_priv_key, sizeof(*ecc_priv_key), 0x0, sizeof(*ecc_priv_key));
        (void)memset_s(ecc_pub_key, sizeof(*ecc_pub_key), 0x0, sizeof(*ecc_pub_key));
        TEE_Free(ecc_priv_key);
        TEE_Free(ecc_pub_key);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if (key_node->key1 != NULL) {
        (void)memset_s(key_node->key1, key_node->key1_size, 0x0, key_node->key1_size);
        TEE_Free(key_node->key1);
        key_node->key1 = NULL;
        key_node->key1_size = 0;
    }
    key_node->key1 = (uint8_t *)ecc_priv_key;
    key_node->key1_size = sizeof(*ecc_priv_key);
    if (key_node->key2 != NULL) {
        (void)memset_s(key_node->key2, key_node->key2_size, 0x0, key_node->key2_size);
        TEE_Free(key_node->key2);
        key_node->key2 = NULL;
        key_node->key2_size = 0;
    }
    key_node->key2 = (uint8_t *)ecc_pub_key;
    key_node->key2_size = sizeof(*ecc_pub_key);
    return KM_ERROR_OK;
}

static keymaster_error_t gp_ec_begin(key_auth * const key_node, TEE_ObjectHandle ec_objecthandle,
    const uint32_t key_size)
{
    bool check_fail = (key_node == NULL || ec_objecthandle == TEE_HANDLE_NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    TEE_OperationMode mode = TEE_MODE_SIGN;
    TEE_OperationHandle ec_operation = TEE_HANDLE_NULL;
    uint32_t algorithm = TEE_ALG_ECDSA_SHA1;
    keymaster_error_t ret = get_ec_pupose(key_node->purpose, &mode);
    if (ret != KM_ERROR_OK) {
        tloge("the purpose %u for ec km_begin is incompatible\n", key_node->purpose);
        return ret;
    }
    ret = get_ec_algorithm(key_node->digest, &algorithm);
    if (ret != KM_ERROR_OK) {
        tloge("the digest %u for ec km_begin may be incompatible\n", key_node->digest);
        return ret;
    }
    if (init_key_operation(&ec_operation, algorithm, mode, key_size, &ec_objecthandle) != TEE_SUCCESS) {
        tloge("TEE allocate and init operation failed, gp_alg 0x%x, mode 0x%x, key_size 0x%x\n",
            algorithm, mode, key_size);
        TEE_FreeOperation(ec_operation);
        ec_operation = TEE_HANDLE_NULL;
        return KM_ERROR_UNKNOWN_ERROR;
    };
    key_node->crypto_ctxt = ec_operation;
    return KM_ERROR_OK;
}
keymaster_error_t operation_ec_begin(key_auth * const key_node, const uint32_t key_size,
    const uint8_t * const keymaterial, const uint32_t version, const struct kb_crypto_factors *factors)
{
    keymaster_error_t ret;
    TEE_ObjectHandle ec_objecthandle = TEE_HANDLE_NULL;
    ret = operation_ec_init_obj((struct keymaterial_ecdsa_header *)keymaterial, &ec_objecthandle, version, factors);
    if (ret != KM_ERROR_OK) {
        tloge("operation ec init object failed.\n");
        goto free_key_obj;
    }
    if (use_soft_engine(key_node))
        ret = soft_ec_begin(key_node, ec_objecthandle);
    else
        ret = gp_ec_begin(key_node, ec_objecthandle, key_size);

    if (ret != KM_ERROR_OK)
        tloge("ec begin failed\n");
free_key_obj:
    TEE_FreeTransientObject(ec_objecthandle);
    ec_objecthandle = TEE_HANDLE_NULL;
    return ret;
}

static keymaster_error_t do_sign_verify_for_operation_ec_finish(key_auth *key_node, uint8_t *in_data,
    uint32_t in_data_size, uint8_t *out_data, uint32_t *out_data_size)
{
    keymaster_error_t ret    = KM_ERROR_OK;
    uint32_t input_data_size = in_data_size;
    bool check_fail = false;
    if (key_node->purpose == KM_PURPOSE_VERIFY) {
        check_fail = ((key_node->digest == KM_DIGEST_MD5 || key_node->digest == KM_DIGEST_NONE) &&
            (key_node->key2 == NULL));
        if (check_fail) {
            tloge("public key is null, but purpose is KM_PURPOSE_VERIFY\n");
            return KM_ERROR_INCOMPATIBLE_PURPOSE;
        }
        ret = ec_sign_verify(key_node, key_node->purpose, key_node->data,
                             key_node->data_size, in_data, &input_data_size);
        if (out_data_size != NULL)
            *out_data_size = 0;
    }
    if (key_node->purpose == KM_PURPOSE_SIGN) {
        check_fail = ((key_node->digest == KM_DIGEST_MD5 || key_node->digest == KM_DIGEST_NONE) &&
            (key_node->key1 == NULL));
        if (check_fail) {
            tloge("private key is null, but purpose is KM_PURPOSE_SIGN\n");
            return KM_ERROR_INCOMPATIBLE_PURPOSE;
        }
        ret = ec_sign_verify(key_node, key_node->purpose, key_node->data,
                             key_node->data_size, out_data, out_data_size);
    }
    return ret;
}

void do_hash_update_for_sign_verify(key_auth *key_node, TEE_OperationHandle digest_contextid_ptr)
{
    if (key_node == NULL)
        return;
    TEE_DigestUpdate(digest_contextid_ptr, key_node->data, key_node->data_size);
    TEE_Free(key_node->data);
    key_node->data = NULL;
    key_node->data_size = 0;
}

keymaster_error_t operation_ec_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_data_size,
    uint8_t *out_data, uint32_t *out_data_size)
{
    if (key_node == NULL) {
        tloge("key_node is null");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    keymaster_error_t ret;
    keymaster_purpose_t purpose = key_node->purpose;
    if ((purpose == KM_PURPOSE_ENCRYPT) || (purpose == KM_PURPOSE_DECRYPT)) {
        tloge("purpose not support %d", purpose);
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }
    if (key_node->digest != KM_DIGEST_NONE) {
        ret = do_hash_for_sign_verify(key_node);
        if (ret != KM_ERROR_OK) {
            tloge("do_hash_for_sign_verify failed\n");
            return ret;
        }
    }
    return do_sign_verify_for_operation_ec_finish(key_node, in_data, in_data_size, out_data, out_data_size);
}

keymaster_error_t operation_ec_update(key_auth *key_node, uint8_t *in_data, uint32_t in_size)
{
    if (key_node == NULL) {
        tloge("key_node is null.\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    bool condition_check = ((key_node->digest == KM_DIGEST_NONE) || (key_node->purpose == KM_PURPOSE_ENCRYPT) ||
        (key_node->purpose == KM_PURPOSE_DECRYPT));
    if (condition_check)
        return asymmetric_update(key_node, in_data, in_size);
    else
        return (keymaster_error_t)asymmetric_hash_update(key_node, in_data, in_size);
}

static keymaster_error_t get_ec_keysize(uint32_t *key_size, keymaster_key_param_set_t *hw_enforced)
{
    bool check_fail = (key_size == NULL || hw_enforced == NULL);
    if (check_fail) {
        tloge("null pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (get_key_param(KM_TAG_KEY_SIZE, key_size, hw_enforced) != 0) {
        /* get ec key_size from keyblob should check KM_TAG_KEY_SIZE or KM_TAG_EC_CURVE */
        uint32_t ec_curve_value = 0;
        if (get_key_param(KM_TAG_EC_CURVE, &ec_curve_value, hw_enforced) != 0) {
            /* must find ec curve while key size not found */
            tloge("get_key_param of ec_curve_value failed\n");
            return KM_ERROR_INVALID_KEY_BLOB;
        }
        if (km_ec_domain_id_to_keysize((keymaster_ec_curve_t)ec_curve_value, key_size) != 0) {
            tloge("get key size from ec curve failed\n");
            return KM_ERROR_INVALID_KEY_BLOB;
        }
    }
    tlogd("get key_size from key blob %u\n", *key_size);
    return KM_ERROR_OK;
}

#define MIN_SECURE_ECDSA_KEY_SIZE 224
static void insecure_ecdsa_alg_prompt(keymaster_digest_t digest, uint32_t key_size)
{
    if (key_size < MIN_SECURE_ECDSA_KEY_SIZE)
        tlogw("Warning: An insecure ecdsa key size is being used, key size = %d\n", key_size);
    if (digest == KM_DIGEST_MD5 || digest == KM_DIGEST_SHA1) {
        tlogw("Warning: An insecure digest for ecdsa is being used: %s, digest id %d\n",
            (digest == KM_DIGEST_MD5) ? "MD5" : "SHA1", digest);
    }
}

keymaster_error_t km_ec_begin(const keymaster_key_param_set_t *params_enforced, const keyblob_head *key_blob,
    key_auth *key_node, const struct kb_crypto_factors *factors)
{
    bool check_fail = (key_node == NULL || key_blob == NULL);
    if (check_fail) {
        tloge("invalid parameters\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    keymaster_error_t ret;
    keymaster_padding_t padding = KM_PAD_NONE;
    keymaster_digest_t digest = KM_DIGEST_NONE;
    uint32_t key_size = 0;
    keymaster_key_param_set_t *hw_enforced =
        (keymaster_key_param_set_t *)((uint8_t *)key_blob + key_blob->hw_enforced_offset);
    /* store key in key_blob and generate operationhandle */
    ret = check_ec_padding_digest_purpose(&padding, &digest, key_node->purpose, hw_enforced, params_enforced);
    if (ret != KM_ERROR_OK) {
        tloge("check ec padding digest purpose failed, 0x%x\n", ret);
        return ret;
    }
    ret = get_ec_keysize(&key_size, hw_enforced);
    if (ret != KM_ERROR_OK) {
        tloge("get ec key size failed\n");
        return ret;
    }
    insecure_ecdsa_alg_prompt(digest, key_size);
    key_node->padding = padding;
    key_node->digest = digest;
    key_node->algorithm = KM_ALGORITHM_EC;

    /*
     * This value could only be used in GP engine. In this situation, the field stores key_size;
     * In sw engine, this filed will be overwritten by the truly private key size value.
     */
    key_node->key1_size = key_size;
    ret = operation_ec_begin(key_node, key_size, (uint8_t *)key_blob + key_blob->keymaterial_offset,
        key_blob->version, factors);
    if (ret != KM_ERROR_OK) {
        tloge("operation ec begin failed, %x\n", ret);
        return ret;
    }
    return KM_ERROR_OK;
}
