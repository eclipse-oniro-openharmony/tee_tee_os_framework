/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster rsa cipher functions implementation
 * Create: 2020-11-09
 */
#include "km_crypto_rsa.h"
#include "securec.h"
#include "keymaster_defs.h"
#include "km_tag_operation.h"
#include "keyblob.h"
#include "openssl/rsa.h"
#include "km_common.h"
#include "km_crypto.h"
#include "km_crypto_sw_engine.h"
#include "km_crypto_adaptor.h"
#include "km_crypto_check.h"
#include "tee_crypto_err.h"

keymaster_error_t preproc_for_rsa_sign_verify(uint32_t key_size_bytes, keymaster_purpose_t purpose,
    keymaster_padding_t padding, keymaster_digest_t digest_mode, uint32_t *digest_len)
{
    int32_t tmp_ret = check_padding_for_rsa_sign_verify(padding);
    if (tmp_ret != 0) {
        tloge("unsupported padding is %d\n", padding);
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }
    tmp_ret = check_purpose_for_rsa_sign_verify(purpose);
    if (tmp_ret != 0) {
        tloge("unsupported purpose %d\n", purpose);
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }
    tmp_ret = (int)get_real_hash_len(digest_mode, digest_len);
    if (tmp_ret != 0) {
        tloge("unsupported digest, digest_mode %d\n", digest_mode);
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    tlogd("digest_len is %u\n", *digest_len);
    /*
     * Use a 512 bit key which should prevent the use of any digests larger than SHA-256
     * because the padded form of the digested message will be larger than modulus size.
     * CTS:RSASignatureTest#testSmallKeyRejected
     */
    if (purpose == KM_PURPOSE_SIGN) {
        /* the calller can ensure pub is not null */
        uint32_t size_bytes = key_size_bytes;
        if (size_bytes == (KEY_SIZE_512 / BITS_ONE_BYTE)) {
            if (digest_mode > KM_DIGEST_SHA_2_256) {
                tloge("key not able to do signature, because size_bytes %u is larger than digest_mode 0x%x\n",
                      size_bytes, digest_mode);
                return KM_ERROR_UNKNOWN_ERROR;
            }
        }
    }
    return KM_ERROR_OK;
}

#define MAX_RSA_E_SIZE 8
static void insecure_rsa_pub_e_check(TEE_ObjectHandle key_obj)
{
    uint8_t e[MAX_RSA_E_SIZE] = { 0 };
    size_t e_len = sizeof(e);
    TEE_Result ret = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_RSA_PUBLIC_EXPONENT, e, &e_len);
    if (ret != TEE_SUCCESS) {
        tloge("get rsa pub exponent failed");
        return;
    }
    uint64_t public_exponent = byte_to_int64(e, e_len);
    if (public_exponent < MIN_INSECURE_RSA_PUB_E)
        tlogw("Warning: An insecure rsa param e is being used: %I64x\n", public_exponent);
}

#define MAX_RSA_KEYPAIR_SIZE 4096U
static keymaster_error_t operation_rsa_init_obj(struct keymaterial_rsa_header *rsa_header,
    TEE_ObjectHandle *rsa_objecthandle, const uint32_t version, const struct kb_crypto_factors *factors)
{
    bool check_fail = (rsa_header == NULL || rsa_objecthandle == NULL || factors == NULL);
    if (check_fail) {
        tloge("null pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    uint8_t temp_buf[MAX_KEY_BUFFER_LEN] = { 0 };
    keymaster_blob_t enc_key = { rsa_header->key, rsa_header->key_buff_len };
    keymaster_blob_t dec_key = { temp_buf, rsa_header->key_buff_len };
    struct keyblob_crypto_ctx ctx = {
        version, (uint32_t)TEE_MODE_DECRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { rsa_header->iv, IV_LEN },
        *factors
    };
    if (keyblob_crypto(&enc_key, &dec_key, &ctx) != TEE_SUCCESS) {
        tloge("keyblob decrypto failed.\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if (init_key_obj(KM_ALGORITHM_RSA, KM_DIGEST_NONE, MAX_RSA_KEYPAIR_SIZE, rsa_objecthandle, &dec_key) !=
        TEE_SUCCESS) {
        tloge("failed to allocate and init key object\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    insecure_rsa_pub_e_check(*rsa_objecthandle);
    (*rsa_objecthandle)->CRTMode = rsa_header->crt_mode;
    return KM_ERROR_OK;
}

static keymaster_error_t gp_rsa_begin(key_auth *key_node, TEE_ObjectHandle rsa_objecthandle)
{
    bool check_fail = (key_node == NULL || rsa_objecthandle == TEE_HANDLE_NULL);
    if (check_fail) {
        tloge("null pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    TEE_OperationMode mode = TEE_MODE_ENCRYPT;
    uint32_t gp_algorithm = TEE_ALG_RSASSA_PKCS1_V1_5_SHA1;
    TEE_OperationHandle op_handle = NULL;
    keymaster_error_t ret = get_rsa_purpose(key_node->purpose, &mode);
    if (ret != KM_ERROR_OK) {
        tloge("the purpose for rsa km_begin is incompatible\n");
        return ret;
    }
    ret = get_rsa_algorithm(key_node->padding, key_node->digest, &gp_algorithm);
    if (ret != KM_ERROR_OK) {
        tloge("the padding %u and digest %u for purpose %u rsa km_begin may be incompatible\n", key_node->padding,
              key_node->digest, key_node->purpose);
        return ret;
    }
    if (init_key_operation(&op_handle, gp_algorithm, mode, key_node->key1_size, &rsa_objecthandle) != TEE_SUCCESS) {
        tloge("alloc and init crypto operation failed\n");
        TEE_FreeOperation(op_handle);
        op_handle = TEE_HANDLE_NULL;
        return KM_ERROR_UNKNOWN_ERROR;
    }
    key_node->crypto_ctxt = (void *)op_handle;
    return KM_ERROR_OK;
}

static keymaster_error_t operation_rsa_begin(key_auth *key_node, keyblob_head *key_blob,
    const struct kb_crypto_factors *factors)
{
    bool check_fail = (key_node == NULL || key_blob == NULL);
    if (check_fail)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    keymaster_error_t ret;
    TEE_ObjectHandle rsa_objecthandle = NULL;
    ret = operation_rsa_init_obj((struct keymaterial_rsa_header *)((uint8_t *)key_blob + key_blob->keymaterial_offset),
        &rsa_objecthandle, key_blob->version, factors);
    if (ret != KM_ERROR_OK) {
        tloge("operation_rsa_init_obj failed.\n");
        goto  free_key_obj;
    }
    if (use_soft_engine(key_node))
        ret = (keymaster_error_t)soft_rsa_begin(rsa_objecthandle, key_node);
    else
        ret = (keymaster_error_t)gp_rsa_begin(key_node, rsa_objecthandle);
    if (ret != KM_ERROR_OK)
        tloge("rsa begin failed\n");
free_key_obj:
    TEE_FreeTransientObject(rsa_objecthandle);
    rsa_objecthandle = TEE_HANDLE_NULL;
    return ret;
}

static keymaster_error_t pre_proc_rsa_encrypt_decrypt(keymaster_padding_t padding, keymaster_purpose_t purpose,
                                                      uint32_t src_len, keymaster_digest_t digest,
                                                      uint32_t key_size_bits)
{
    keymaster_error_t ret;
    if (check_padding_for_rsa_enc_dec(padding)) {
        tloge("unsupported padding is %d\n", padding);
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }
    if (check_purpose_for_rsa_enc_dec(purpose)) {
        tloge("unsupported purpose %d\n", purpose);
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }

    if (purpose == KM_PURPOSE_ENCRYPT) {
        ret = rsa_indata_size_larger_modulus(src_len, padding, digest, key_size_bits);
        tlogd("tcm RSA IndataSize Larger Modulus ret is %d\n", ret);
        if (ret != KM_ERROR_OK) {
            tloge("input data larger than modulus\n");
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
    }
    return KM_ERROR_OK;
}

static void rsa_finish_for_null_input_size(const key_auth *key_node, uint32_t *out_data_size)
{
    uint32_t key_size_bytes = key_node->key1_size / BITS_ONE_BYTE;
    bool condition = (key_node->padding == KM_PAD_RSA_PKCS1_1_5_ENCRYPT || key_node->padding == KM_PAD_RSA_OAEP);
    if (condition)
        *out_data_size = 0;
    if (key_node->padding == KM_PAD_NONE)
        *out_data_size = key_size_bytes;
}

static keymaster_error_t rsa_finish_for_shorter_input_size(key_auth *key_node)
{
    uint32_t key_size_bytes = key_node->key1_size / BITS_ONE_BYTE;
    uint8_t *temp_buf = (uint8_t *)TEE_Malloc(key_size_bytes, TEE_MALLOC_FILL_ZERO);
    if (temp_buf == NULL) {
        tloge("malloc failed\n");
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    int32_t rc = memcpy_s(temp_buf + key_size_bytes - key_node->data_size, key_node->data_size,
                          key_node->data, key_node->data_size);
    if (rc != EOK) {
        TEE_Free(temp_buf);
        temp_buf = NULL;
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    TEE_Free(key_node->data);
    key_node->data = temp_buf;
    key_node->data_size = key_size_bytes;
    return KM_ERROR_OK;
}

static keymaster_error_t rsa_enc_decrypt_finsh(key_auth *key_node, uint8_t *out_data, uint32_t *out_data_size,
    size_t *out_len, int force, keymaster_purpose_t purpose)
{
    keymaster_error_t ret;
    TEE_Result result;
    uint32_t key_size_bytes = key_node->key1_size / BITS_ONE_BYTE;
    bool condition = (key_node->data == NULL || key_node->data_size == 0);
    if (condition) {
        rsa_finish_for_null_input_size(key_node, out_data_size);
        return KM_ERROR_OK;
    }
    condition = (key_node->padding == KM_PAD_NONE && key_node->data_size < key_size_bytes);
    if (condition) {
        ret = rsa_finish_for_shorter_input_size(key_node);
        if (ret != KM_ERROR_OK)
            return ret;
    }
    if (purpose == KM_PURPOSE_ENCRYPT) {
        if (*out_data_size < key_size_bytes) {
            tloge("The buffer must be at least modulus size bytes long\n");
            return KM_ERROR_OUTPUT_PARAMETER_NULL;
        }
        result = TEE_AsymmetricEncrypt((TEE_OperationHandle)key_node->crypto_ctxt, NULL, 0, key_node->data,
            key_node->data_size, out_data, out_len);
        if (force == 0 && result != TEE_SUCCESS) {
            tloge("TEE_AsymmetricEncrypt failed, result=%x\n", result);
            /*
            * with different error return, we need to return the correct KM_ERROR_XXX,
            * the error code come from hardware crypto and we change it for CTS
            */
            if (result == TEE_ERR_RSA_R_DATA_TOO_LARGE_FOR_MODULUS)
                return KM_ERROR_INVALID_ARGUMENT;
            return KM_ERROR_UNKNOWN_ERROR;
        }
    } else {
        result = TEE_AsymmetricDecrypt((TEE_OperationHandle)key_node->crypto_ctxt, NULL, 0, key_node->data,
            key_node->data_size, out_data, out_len);
        if (force == 0 && result != TEE_SUCCESS) {
            tloge("TEE_AsymmetricDecrypt failed, result=%x\n", result);
            return KM_ERROR_UNKNOWN_ERROR;
        }
    }
    *out_data_size = *out_len;
    return KM_ERROR_OK;
}

static keymaster_error_t rsa_sign_verify_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_data_size,
    uint8_t *out_data, size_t *out_len, int force, keymaster_purpose_t purpose)
{
    TEE_Result result;
    uint32_t digest_lenth = key_node->data_size;
    keymaster_error_t ret = preproc_for_rsa_sign_verify(((TEE_OperationHandle)key_node->crypto_ctxt)->keySize, purpose,
        key_node->padding, key_node->digest, &digest_lenth);
    if (ret != KM_ERROR_OK)
        return ret;
    if (purpose == KM_PURPOSE_SIGN) {
        result = TEE_AsymmetricSignDigest((TEE_OperationHandle)key_node->crypto_ctxt, NULL, 0, key_node->data,
            digest_lenth, out_data, out_len);
        if (force == 0 && result != TEE_SUCCESS) {
            tloge("TEE_AsymmetricSignDigest failed, result=%x\n", result);
            return KM_ERROR_UNKNOWN_ERROR;
        }
    } else {
        result = TEE_AsymmetricVerifyDigest((TEE_OperationHandle)key_node->crypto_ctxt, NULL, 0, key_node->data,
                                            digest_lenth, in_data, in_data_size);
        if (force == 0 && result != TEE_SUCCESS) {
            tloge("TEE_AsymmetricVerifyDigest failed, result=%x\n", result);
            return KM_ERROR_VERIFICATION_FAILED;
        }
        if (out_len != NULL)
            *out_len = 0;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t proc_operation_rsa_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_data_size,
                                                   uint8_t *out_data, uint32_t *out_data_size, int force,
                                                   keymaster_purpose_t purpose)
{
    keymaster_error_t ret;
    if (force == 1)
        return KM_ERROR_OK;
    if (out_data_size == NULL) {
        tloge("out_data_size is NULL in proc_operation_rsa_finish\n");
        return KM_ERROR_INVALID_ARGUMENT;
    }
    size_t out_len = *out_data_size;
    if ((purpose == KM_PURPOSE_ENCRYPT) || (purpose == KM_PURPOSE_DECRYPT)) {
        return rsa_enc_decrypt_finsh(key_node, out_data, out_data_size, &out_len, force, purpose);
    } else if ((purpose == KM_PURPOSE_SIGN) || (purpose == KM_PURPOSE_VERIFY)) {
        ret = rsa_sign_verify_finish(key_node, in_data, in_data_size, out_data, &out_len, force, purpose);
        *out_data_size =  out_len;
        return ret;
    } else {
        tloge("invalid purpose %d\n", purpose);
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }
}

static keymaster_error_t operation_rsa_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_data_size,
                                              uint8_t *out_data, uint32_t *out_data_size, int force)
{
    keymaster_error_t ret;
    keymaster_purpose_t purpose = key_node->purpose;
    bool condition_check = ((purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_VERIFY) &&
        (key_node->digest != KM_DIGEST_NONE && key_node->padding != KM_PAD_NONE));
    if (condition_check) {
        ret = do_hash_for_sign_verify(key_node);
        if (ret != KM_ERROR_OK) {
            tloge("rsa finish to hash fail");
            return ret;
        }
    }
    condition_check = (purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_DECRYPT);
    if (condition_check) {
        ret = pre_proc_rsa_encrypt_decrypt(key_node->padding, key_node->purpose, key_node->data_size,
            key_node->digest, key_node->key1_size);
        if (ret != KM_ERROR_OK) {
            tloge("pre_proc_rsa_encrypt_decrypt failed\n");
            return ret;
        }
    }
    if (use_soft_engine(key_node)) {
        if (force == 1)
            return KM_ERROR_OK;
        condition_check = (purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_DECRYPT);
        if (condition_check) {
            /* only OAEP padding with MD5 digest using soft engin while do Enc/Dec operation */
            ret = oaep_pad_for_rsa_enc_dec(key_node, key_node->purpose, key_node->data, key_node->data_size, out_data,
                out_data_size, force);
        } else if (purpose == KM_PURPOSE_SIGN) {
            ret = soft_rsa_sign_verify(key_node, purpose, key_node->data, key_node->data_size,
                out_data, out_data_size);
        } else if (purpose == KM_PURPOSE_VERIFY) {
            ret = soft_rsa_sign_verify(key_node, purpose, key_node->data, key_node->data_size,
                in_data, &in_data_size);
            if (out_data_size != NULL)
                *out_data_size = 0;
        } else {
            tloge("inavlid purpose %d\n", purpose);
            return KM_ERROR_UNSUPPORTED_PURPOSE;
        }
        if (ret != TEE_SUCCESS)
            tloge("rsa soft fail 0x%x", ret);
        return ret;
    }
    return proc_operation_rsa_finish(key_node, in_data, in_data_size, out_data, out_data_size, force, purpose);
}

keymaster_error_t operation_rsa_update(key_auth *key_node, uint8_t *in_data, uint32_t in_size)
{
    if (key_node == NULL) {
        tloge("key_node is null");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    bool condition_check = ((key_node->digest == KM_DIGEST_NONE) || (key_node->purpose == KM_PURPOSE_ENCRYPT) ||
        (key_node->purpose == KM_PURPOSE_DECRYPT));
    if (condition_check) {
        if (check_operation_rsa_update(key_node, in_size) != KM_ERROR_OK) {
            tloge("check_operation_rsa_update failed");
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
        return asymmetric_update(key_node, in_data, in_size);
    } else {
        return (keymaster_error_t)asymmetric_hash_update(key_node, in_data, in_size);
    }
}

keymaster_error_t proc_rsa_operation_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_size,
    uint8_t *out_data, uint32_t *out_size, int force)
{
    if (key_node == NULL) {
        tloge("key_node is null");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (in_data == NULL)
        return operation_rsa_finish(key_node, key_node->data, key_node->data_size, out_data, out_size, force);
    else
        return operation_rsa_finish(key_node, in_data, in_size, out_data, out_size, force);
}

static keymaster_error_t check_rsa_padding_digest(keymaster_padding_t *padding, keymaster_digest_t *digest,
    const keymaster_key_param_set_t *params_enforced, key_auth *key_node, keymaster_key_param_set_t *hw_enforced)
{
    bool check_failed = (padding == NULL || digest == NULL || params_enforced == NULL || key_node == NULL ||
        hw_enforced == NULL);
    if (check_failed) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    /* must get from padding input params_enforced, because the key params may have multiple PADDINGS or DIGESTS */
    keymaster_error_t ret = check_rsa_padding_params(padding, params_enforced, key_node->purpose, hw_enforced);
    if (ret != KM_ERROR_OK) {
        tloge("check_rsa_padding_params of keymaster padding failed\n");
        return ret;
    }
    /* must get from digest input params_enforced */
    ret = check_rsa_diagest_params(*padding, key_node->purpose, digest, params_enforced, hw_enforced);
    if (ret != KM_ERROR_OK) {
        tloge("check rsa digest params of keymaster padding failed\n");
        return ret;
    }
    tlogd("padding is %d, digest is %d\n", *padding, *digest);
    ret = check_rsa_digest_is_valid(*padding, *digest);
    if (ret != KM_ERROR_OK)
        tloge("check_rsa_digest_is_valid of keymaster failed\n");
    return ret;
}

static keymaster_error_t check_rsa_padding_digest_keysize(keymaster_padding_t padding, keymaster_digest_t digest,
    uint32_t *key_size, keymaster_key_param_set_t *hw_enforced)
{
    bool check_fail = (key_size == NULL || hw_enforced == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (get_key_param(KM_TAG_KEY_SIZE, key_size, hw_enforced) != 0) {
        tloge("get_key_param of key_size failed\n");
        return (keymaster_error_t)TEE_ERROR_BAD_PARAMETERS;
    }
    keymaster_error_t ret = check_rsa_digest_mode(padding, digest, *key_size);
    if (ret != KM_ERROR_OK) {
        tloge("check_rsa_digest_mode of keymaster failed\n");
        return KM_ERROR_INCOMPATIBLE_DIGEST;
    }
    return KM_ERROR_OK;
}

#define MIN_SECURE_RSA_KEY_SIZE 2048
static void insecure_rsa_alg_prompt(keymaster_padding_t padding, keymaster_digest_t digest, uint32_t key_size)
{
    if (key_size < MIN_SECURE_RSA_KEY_SIZE)
        tlogw("Warning: An insecure rsa key size is being used, key size = %d\n", key_size);
    if (digest == KM_DIGEST_MD5 || digest == KM_DIGEST_SHA1) {
        tlogw("Warning: An insecure digest for rsa is being used: %s, digest id %d\n",
            (digest == KM_DIGEST_MD5) ? "MD5" : "SHA1", digest);
    }
    if (padding == KM_PAD_RSA_PKCS1_1_5_SIGN || padding == KM_PAD_RSA_PKCS1_1_5_ENCRYPT)
        tlogw("Warning: An insecure padding is being used, pkcs1_v1_5 padding\n");
}

keymaster_error_t km_rsa_begin(const keymaster_key_param_set_t *params_enforced, keyblob_head *key_blob,
    key_auth *key_node, const struct kb_crypto_factors *factors)
{
    bool check_fail = (key_node == NULL || key_blob == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    keymaster_error_t ret;
    keymaster_padding_t padding = KM_PAD_NONE;
    keymaster_digest_t digest = KM_DIGEST_NONE;
    uint32_t key_size = 0;
    keymaster_key_param_set_t *hw_enforced =
        (keymaster_key_param_set_t *)((uint8_t *)key_blob + key_blob->hw_enforced_offset);
    /* must get from padding input params_enforced, because the key params may have multiple PADDINGS or DIGESTS */
    ret = check_rsa_padding_digest(&padding, &digest, params_enforced, key_node, hw_enforced);
    if (ret != KM_ERROR_OK) {
        tloge("padding digest check failed\n");
        return ret;
    }
    ret = check_rsa_padding_digest_keysize(padding, digest, &key_size, hw_enforced);
    if (ret != KM_ERROR_OK) {
        tloge("check rsa padding, digest, keysize failed\n");
        return ret;
    }
    insecure_rsa_alg_prompt(padding, digest, key_size);
    key_node->padding = padding;
    key_node->digest = digest;
    key_node->key1_size = key_size;
    tlogd("km rsa begin, algorithm %u, purpose %u, padding %u, digest %u\n", key_node->algorithm, key_node->purpose,
        key_node->padding, key_node->digest);
    ret = operation_rsa_begin(key_node, key_blob, factors);
    if (ret != KM_ERROR_OK) {
        tloge("operation rsa begin failed.\n");
        return ret;
    }
    return KM_ERROR_OK;
}
