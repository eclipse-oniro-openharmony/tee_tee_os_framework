/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: common crypto process for keymaster
 * Create: 2020-11-09
 */

#include "km_crypto.h"
#include "securec.h"
#include "km_tag_operation.h"
#include "keyblob.h"
#include "crypto_wrapper.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"
#ifdef BORINGSSL_ENABLE
#include "openssl/nid.h"
#else
#include "openssl/obj_mac.h"
#endif
#include "km_attest_factory.h"
#include "km_common.h"
#include "km_crypto_hmac.h"
#include "km_crypto_check.h"
#include "km_crypto_rsa.h"
#include "km_crypto_ecdsa.h"
#include "km_crypto_aes.h"
#include "km_crypto_adaptor.h"
#include "km_env.h"
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
#include "km_key_enhanced.h"
#endif
/* 12 mean nonce size */
static const uint32_t g_gcm_nonce_size = 12;
int32_t hmac_with_key(uint8_t *key, const uint8_t *src, uint32_t src_size, uint8_t *dst, uint32_t dst_size)
{
    bool check_fail = (key == NULL || src == NULL || dst == NULL);
    if (check_fail) {
        tloge("input is null\n");
        return -1;
    }
    TEE_Result ret;
    errno_t rc;
    int32_t ret_value = 0;
    size_t dst_buf_len = dst_size;
    TEE_ObjectHandle key_object = TEE_HANDLE_NULL;
    TEE_OperationHandle hmac_ops = TEE_HANDLE_NULL;
    key_object = hmac_sha256_generate_keyobject(key);
    if (key_object == TEE_HANDLE_NULL) {
        tloge("Err input KEY, generate key object failed\n");
        ret_value = -1;
        goto release;
    }
    ret = init_key_operation(&hmac_ops, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, HMAC_MAX_KEY_SIZE_BITS, &key_object);
    if (ret != TEE_SUCCESS) {
        tloge("allocate and init operation failed, ret 0x%x\n", ret);
        ret_value = -1;
        goto free_ops;
    }

    TEE_MACInit(hmac_ops, NULL, 0);
    ret = TEE_MACComputeFinal(hmac_ops, (void *)src, (size_t)src_size, (void *)dst, &dst_buf_len);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_MAC ComputeFinal failed, ret=0x%x\n", ret);
        ret_value = -1;
    }
free_ops:
    TEE_FreeOperation(hmac_ops);
    hmac_ops = TEE_HANDLE_NULL;
release:
    TEE_FreeTransientObject(key_object);
    key_object = TEE_HANDLE_NULL;
    rc = memset_s(key, AES_KEY_LEN, 0, AES_KEY_LEN);
    if (rc != EOK) {
        tloge("memset_s failed, rc 0x%x\n", rc);
        return -1;
    }
    return ret_value;
}

int32_t hash_compare(const uint8_t *buf, uint32_t buf_len, const uint8_t *hash)
{
    bool check_fail = ((buf == NULL) || (hash == NULL) || (buf_len == 0));
    if (check_fail) {
        tloge("invalid input params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t hash_buf[SHA256_LENGTH] = { 0 };

    /* hash */
    uint8_t *result = SHA256(buf, buf_len, hash_buf);
    if (result == NULL) {
        tloge("TEE_EXT_HASH failed");
        return AT_SIGN_HASH_ERR;
    }
    if (TEE_MemCompare(hash_buf, hash, SHA256_LENGTH)) {
        tloge("hash compare failed, input is invalid\n");
        return AT_HASH_CHECK_ERR;
    }
    tlogd("hash_compare success\n");
    return 0;
}

int32_t do_sign_func(uint32_t *sig_out_len, uint8_t *hash_buf, uint8_t *out, const struct dev_key_t *dev_key)
{
    int32_t ret;
    if (dev_key->alg == ALG_EC) {
        ret = ecc_sign_digest(out, *sig_out_len, hash_buf, SHA256_LENGTH, (ecc_priv_key_t *)dev_key->prv_key.data_addr);
    } else if (dev_key->alg == ALG_RSA) {
        /* use sw engine rsa_pkcs1v1_5_sign_digest */
        ret = rsa_sign_digest(out, sig_out_len, hash_buf, SHA256_LENGTH, (rsa_priv_key_t *)dev_key->prv_key.data_addr,
                              0, NID_sha256, RSA_PKCS1_PADDING);
        if (ret < 0) {
            tloge("cert rsa sign error");
            return AT_SIGN_ERR;
        }
        ret = *sig_out_len;
    } else {
        tloge("invalid dev_key alg:%d\n", dev_key->alg);
        return AT_SIGN_ERR;
    }
    return ret;
}

static int32_t pre_proc_have_data_for_asymmetric_hash_update(const key_auth *key_node, uint8_t *temp_buffer,
                                                             uint32_t hash_len)
{
    errno_t rc;
    /* key_node->data_size must less than hash_len */
    if (key_node->data_size >= hash_len) {
        tloge("key_node->data_size %u is not correct, larger or equal to hash_len %u\n", key_node->data_size, hash_len);
        return -1;
    }
    /* update last not update block */
    rc = memcpy_s(temp_buffer, hash_len, key_node->data, key_node->data_size);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        return -1;
    }
    return 0;
}

static int32_t proc_data_not_align_len(key_auth *key_node, uint32_t data_not_align_len, uint8_t **data_update,
                                       uint32_t *data_update_len, uint8_t *temp_in_data, uint32_t *temp_in_data_len)
{
    errno_t rc;
    uint8_t *data_not_align = NULL;

    /* if data not aligned, should copy last data to key_node->data */
    data_not_align = (uint8_t *)TEE_Malloc(data_not_align_len, 0);
    if (data_not_align == NULL) {
        tloge("current block failed to mallco for data_not_align, data_not_align_len is %u\n", data_not_align_len);
        return -1;
    }
    rc = memcpy_s(data_not_align, data_not_align_len, temp_in_data + (*temp_in_data_len - data_not_align_len),
                  data_not_align_len);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        TEE_Free(data_not_align);
        return -1;
    }
    TEE_Free(key_node->data);
    key_node->data      = data_not_align;
    key_node->data_size = data_not_align_len;
    *temp_in_data_len   = *temp_in_data_len - data_not_align_len;
    *data_update        = temp_in_data;
    *data_update_len    = *temp_in_data_len;
    return 0;
}

static int32_t proc_more_than_hash_len(key_auth *key_node, uint8_t *temp_buffer, TEE_OperationHandle operation,
                                       uint8_t **data_update, uint32_t *data_update_len, uint32_t hash_len,
                                       uint8_t *datain_ptr, uint32_t data_size)
{
    errno_t rc;
    int32_t ret;
    uint8_t *temp_in_data = NULL;
    uint32_t data_not_align_len;
    uint32_t temp_in_data_len;

    /* else combine the key_node data to in data to one block then do update */
    rc = memcpy_s(temp_buffer + key_node->data_size, (hash_len - key_node->data_size), datain_ptr,
                  (hash_len - key_node->data_size));
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        return -1;
    }
    TEE_DigestUpdate(operation, temp_buffer, hash_len);

    TEE_Free(key_node->data);
    temp_in_data        = (datain_ptr + hash_len) - key_node->data_size;
    temp_in_data_len    = (data_size - (hash_len - key_node->data_size));
    key_node->data      = NULL;
    key_node->data_size = 0;
    if (temp_in_data_len == 0) {
        /* if the block size + key_node data size equal with hlen, no need update in the end of this function */
        *data_update     = NULL;
        *data_update_len = 0;
    } else {
        data_not_align_len = temp_in_data_len % hash_len;
        if (data_not_align_len != 0) {
            ret = proc_data_not_align_len(key_node, data_not_align_len, data_update, data_update_len, temp_in_data,
                                          &temp_in_data_len);
            if (ret != 0) {
                tloge("proc_data_not_align_len failed\n");
                return -1;
            }
        } else {
            /* if data aligned just do update */
            *data_update     = temp_in_data;
            *data_update_len = temp_in_data_len;
        }
    }
    return 0;
}

static int32_t proc_have_data_for_asymmetric_hash_update(key_auth *key_node, TEE_OperationHandle operation,
                                                         uint8_t **data_update, uint32_t *data_update_len,
                                                         uint32_t hash_len, uint8_t *datain_ptr, uint32_t data_size)
{
    uint8_t *temp_buffer = NULL;
    int32_t ret;
    errno_t rc;

    temp_buffer = TEE_Malloc(hash_len, 0);
    if (temp_buffer == NULL) {
        tloge("failed to mallco for temp_buffer, len is %u\n", hash_len);
        return -1;
    }
    ret = pre_proc_have_data_for_asymmetric_hash_update(key_node, temp_buffer, hash_len);
    if (ret != 0) {
        tloge("pre_proc_have_data_for_asymmetric_hash_update failed.\n");
        goto error_exit;
    }
    /* if Datasize+key_node->data_size less than hash_len, this block will not do update */
    if (data_size < (hash_len - key_node->data_size)) {
        rc = memcpy_s(temp_buffer + key_node->data_size, hash_len - key_node->data_size, datain_ptr, data_size);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            goto error_exit;
        }
        TEE_Free(key_node->data);
        key_node->data      = temp_buffer;
        key_node->data_size = key_node->data_size + data_size;
        *data_update        = NULL;
        *data_update_len    = 0;
    } else {
        ret = proc_more_than_hash_len(key_node, temp_buffer, operation, data_update, data_update_len,
                                      hash_len, datain_ptr, data_size);
        if (ret != 0) {
            tloge("proc_more_than_hash_len failed\n");
            goto error_exit;
        }
        TEE_Free(temp_buffer);
        temp_buffer = NULL;
    }

    return 0;
error_exit:
    TEE_Free(temp_buffer);
    temp_buffer = NULL;
    return -1;
}

static int32_t proc_no_data_for_asymmetric_hash_update(key_auth *key_node, uint8_t **data_update,
                                                       uint32_t *data_update_len, uint32_t hash_len,
                                                       uint8_t *datain_ptr, uint32_t data_size)
{
    uint8_t *data_not_align = NULL;
    uint32_t data_not_align_len;
    errno_t rc;

    /* not align block */
    if (hash_len == 0) {
        tloge("hash len is 0");
        return -1;
    }
    data_not_align_len = data_size % hash_len;
    if (data_not_align_len != 0) {
        data_not_align = (uint8_t *)TEE_Malloc(data_not_align_len, 0);
        if (data_not_align == NULL) {
            tloge("failed to mallco for data_not_align, data_not_align_len is %u\n", data_not_align_len);
            return -1;
        }
        rc = memcpy_s(data_not_align, data_not_align_len, datain_ptr + (data_size - data_not_align_len),
                      data_not_align_len);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            TEE_Free(data_not_align);
            data_not_align = NULL;
            return -1;
        }
        TEE_Free(key_node->data);
        key_node->data      = data_not_align;
        key_node->data_size = data_not_align_len;
        *data_update        = datain_ptr;
        *data_update_len    = data_size - data_not_align_len;
    } else {
        *data_update     = datain_ptr;
        *data_update_len = data_size;
    }

    return 0;
}

int32_t proc_asymmetric_hash_update(key_auth *key_node, TEE_OperationHandle operation, uint8_t **data_update,
    uint32_t *data_update_len, uint32_t hash_len, uint8_t *datain_ptr, uint32_t data_size)
{
    int32_t ret;

    if (key_node->data == NULL) {
        ret = proc_no_data_for_asymmetric_hash_update(key_node, data_update, data_update_len, hash_len, datain_ptr,
                                                      data_size);
        if (ret == -1) {
            tloge("proc_no_data_for_asymmetric_hash_update failed\n");
            return -1;
        }
    } else {
        ret = proc_have_data_for_asymmetric_hash_update(key_node, operation, data_update, data_update_len,
                                                        hash_len, datain_ptr, data_size);
        if (ret == -1) {
            tloge("proc_have_data_for_asymmetric_hash_update failed\n");
            return -1;
        }
    }
    return 0;
}

static keymaster_error_t check_iv(keymaster_algorithm_t algorithm, keymaster_block_mode_t block_mode, const uint8_t *iv)
{
    bool condition = (((algorithm == KM_ALGORITHM_AES &&
        (block_mode == KM_MODE_CBC || block_mode == KM_MODE_CTR || block_mode == KM_MODE_GCM)) ||
        (algorithm == KM_ALGORITHM_TRIPLE_DES && block_mode == KM_MODE_CBC)) && (iv == NULL));
    if (condition) {
        tloge("iv is needed\n");
        return KM_ERROR_MISSING_NONCE;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t asymmetric_update_first(key_auth *key_node, uint32_t in_size)
{
    if (key_node->data != NULL) {
        TEE_Free(key_node->data);
        key_node->data = NULL;
    }
    key_node->data = (uint8_t *)TEE_Malloc(in_size, 0);
    if (key_node->data == NULL) {
        tloge("key_node->data malloc failed:in_size is %u\n", in_size);
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    key_node->data_size = 0;
    return KM_ERROR_OK;
}

keymaster_error_t asymmetric_update(key_auth *key_node, const uint8_t *in_data, uint32_t in_size)
{
    errno_t rc;
    bool condition_check = ((key_node == NULL) || (in_data == NULL));
    if (condition_check) {
        tloge("key_node or in_data is null\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    /* store data */
    condition_check = ((key_node->data == NULL) || (key_node->data_size == 0));
    if (condition_check) {
        keymaster_error_t ret = asymmetric_update_first(key_node, in_size);
        if (ret != KM_ERROR_OK) {
            tloge("key_node data init fail\n");
            return ret;
        }
    } else {
        if (key_node->data_size > (UINT32_MAX - in_size)) {
            tloge("in_data size invalid:%u\n", in_size);
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
        uint8_t *temp_buf = (uint8_t *)TEE_Malloc(key_node->data_size + in_size, 0);
        if (temp_buf == NULL) {
            tloge("key_node->data malloc failed:key_node->data_size is %u, in_size is %u\n", key_node->data_size,
                  in_size);
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        rc = memcpy_s(temp_buf, key_node->data_size + in_size, key_node->data, key_node->data_size);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            TEE_Free(temp_buf);
            temp_buf = 0;
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        TEE_Free(key_node->data);
        key_node->data = temp_buf;
    }
    rc = memcpy_s(key_node->data + key_node->data_size, in_size, in_data, in_size);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        TEE_Free(key_node->data);
        key_node->data      = NULL;
        key_node->data_size = 0;
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    key_node->data_size += in_size;
    return KM_ERROR_OK;
}

static int32_t get_value_by_type_and_len(uint8_t type, int32_t len, uint8_t *ptr, keymaster_blob_t *input,
    keymaster_blob_t *signature)
{
    if (type == FINAL_INPUT) {
        if (len > 0 && (input != NULL))
            input->data_addr = ptr;
        if (input != NULL)
            input->data_length = (uint32_t)len;
    } else if (type == FINAL_SIG) {
        if (len > 0 && signature != NULL)
            signature->data_addr = ptr;
        if (signature != NULL)
            signature->data_length = (uint32_t)len;
    } else {
        tloge("invalid final input first type:%u\n", type);
        return -1;
    }

    return 0;
}

int extract_final_input(const keymaster_blob_t *in_data, keymaster_blob_t *input, keymaster_blob_t *signature)
{
    int32_t ret;
    bool check_fail = (in_data == NULL || in_data->data_addr == NULL);
    if (check_fail) {
        tloge("in_data is null\n");
        return -1;
    }
    uint32_t header_len = sizeof(uint32_t) + sizeof(uint8_t);
    if (in_data->data_length < (header_len * HEAD_NUM)) {
        tloge("extract final input error, invalid final buffer len:%u\n", in_data->data_length);
        return -1;
    }
    uint32_t in_size = in_data->data_length;
    /* type */
    uint8_t *ptr = in_data->data_addr;
    uint8_t type = *ptr;
    ptr++;
    /* length */
    int32_t len = get_next_int4(&ptr);
    in_size -= header_len;
    if (length_check(len, (int)in_size)) {
        tloge("invalid final input len:%d\n", len);
        return -1;
    }
    /* value */
    ret = get_value_by_type_and_len(type, len, ptr, input, signature);
    if (ret == -1) {
        tloge("get_value_by_type_and_len failed.\n");
        return -1;
    }
    ptr += len;
    in_size -= len;

    if (in_size < header_len) {
        tloge("in_size small than header_len\n");
        return -1;
    }
    type = *ptr;
    ptr++;
    /* length */
    len = get_next_int4(&ptr);
    in_size -= header_len;
    if ((len < 0) || ((int)in_size < len)) {
        tloge("invalid final input second len:%d\n", len);
        return -1;
    }
    /* value */
    ret = get_value_by_type_and_len(type, len, ptr, input, signature);
    if (ret == -1) {
        tloge("get_value_by_type_and_len failed.\n");
        return -1;
    }
    return 0;
}

static keymaster_error_t proc_all_algorithm_for_operation_update(key_auth *key_node,
                                                                 const keymaster_key_param_set_t *params_enforced,
                                                                 uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                                                 uint32_t *out_size)
{
    keymaster_error_t ret = KM_ERROR_UNSUPPORTED_ALGORITHM;
    if (key_node == NULL) {
        tloge("can't find auth node");
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    switch (key_node->algorithm) {
    case KM_ALGORITHM_RSA:
        ret = operation_rsa_update(key_node, in_data, in_size);
        *out_size = 0;
        break;
    case KM_ALGORITHM_EC:
        ret = operation_ec_update(key_node, in_data, in_size);
        *out_size = 0;
        break;
    case KM_ALGORITHM_AES:
        if (key_node->block_mode == KM_MODE_GCM)
            ret = proc_aes_gcm_for_operation_update(key_node, params_enforced, in_data, in_size, out_data, out_size);
        else
            ret = km_aes_update(key_node, in_data, in_size, out_data, out_size);
        break;
    case KM_ALGORITHM_TRIPLE_DES:
        ret = triple_des_update(key_node, in_data, in_size, out_data, out_size);
        break;
    case KM_ALGORITHM_HMAC:
        ret = km_hmac_update(key_node, in_data, in_size);
        *out_size = 0;
        break;
    default:
        break;
    }
    return ret;
}

keymaster_error_t operation_update(uint64_t operation_handle, const keymaster_key_param_set_t *params_enforced,
                                   keymaster_blob_t *in_data, keymaster_blob_t *out_data)
{
    keymaster_error_t ret;
    key_auth *key_node = NULL;
    TEE_Result find;
    bool con = (in_data == NULL || out_data == NULL || out_data->data_addr == NULL);
    if (con) {
        tloge("null pointers\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    find = get_auth_node(operation_handle, &key_node);
    con = (find != TEE_SUCCESS || key_node == NULL);
    if (con) {
        tloge("can't find auth node");
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    /* in_size is the length of input data for this call update command, and it's value is not larger than 512k. */
    con = (((key_node->algorithm != KM_ALGORITHM_AES || key_node->block_mode != KM_MODE_GCM) &&
        (in_data->data_addr == NULL || in_data->data_length == 0)) || in_data->data_length > FIXED_CHUNKSIZE_CA);
    if (con) {
        tloge("invalid input data, size %u\n", in_data->data_length);
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }
    tlogd("key_node->algorithm is 0x%x\n", key_node->algorithm);
    ret = proc_all_algorithm_for_operation_update(key_node, params_enforced, in_data->data_addr, in_data->data_length,
        out_data->data_addr, &(out_data->data_length));
    if (ret != KM_ERROR_OK)
        tloge("algorithm %d update failed, ret is 0x%x\n", key_node->algorithm, ret);
    return ret;
}

static keymaster_error_t proc_symmetric_begin(key_auth *key_node, keymaster_blob_t *key,
    keymaster_blob_t *iv)
{
    if (key_node->algorithm == KM_ALGORITHM_AES)
        return km_aes_begin(key_node, iv, key);
    else if (key_node->algorithm == KM_ALGORITHM_HMAC)
        return km_hmac_begin(key_node, key);
    else if (key_node->algorithm == KM_ALGORITHM_TRIPLE_DES)
        return km_3des_begin(key_node, key, iv);
    else
        return KM_ERROR_UNSUPPORTED_ALGORITHM;
}

static keymaster_error_t prepare_symmetric_begin(key_auth *key_node, const keymaster_blob_t *iv)
{
    keymaster_error_t ret;
    /* check iv */
    ret = check_iv(key_node->algorithm, key_node->block_mode, iv->data_addr);
    if (ret) {
        tloge("check_IV failed\n");
        return ret;
    }
    if (key_node->block_mode == KM_MODE_GCM)
        key_node->data_started_gcm = false;
    return KM_ERROR_OK;
}
static keymaster_error_t operation_symmetric_begin(key_auth *key_node, keymaster_blob_t *key, keymaster_blob_t *iv)
{
    if (key_node == NULL) {
        tloge("key_node is null");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    keymaster_error_t ret;
    ret = prepare_symmetric_begin(key_node, iv);
    if (ret != KM_ERROR_OK) {
        tloge("prepare symmetric begin failed");
        return ret;
    }
    return proc_symmetric_begin(key_node, key, iv);
}

static keymaster_error_t operation_symmetric_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_size,
                                                    uint8_t *out_data, uint32_t *out_size, int force)
{
    if (key_node == NULL) {
        tloge("key_node is null");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    keymaster_error_t ret = KM_ERROR_OK;
    if (key_node->algorithm == KM_ALGORITHM_AES) {
        ret = km_aes_finish(key_node, in_data, in_size, out_data, out_size, force);
    } else if (key_node->algorithm == KM_ALGORITHM_TRIPLE_DES) {
        ret = triple_des_finish(key_node, in_data, in_size, out_data, out_size, force);
    } else if (key_node->algorithm == KM_ALGORITHM_HMAC) {
        ret = hmac_finish(key_node, in_data, in_size, out_data, out_size, force);
    } else {
        tloge("unsupport algorithm %d\n", key_node->algorithm);
        return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }

    if ((force == 0) && (ret != KM_ERROR_OK)) {
        tloge("algorithm %d finish failed, ret is 0x%x\n", key_node->algorithm, ret);
        return ret;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t preproc_operation_finish(key_auth *key_node, keymaster_blob_t *in_data)
{
    keymaster_blob_t input = { NULL, 0 };
    keymaster_blob_t signature = { NULL, 0 };
    keymaster_error_t ret = (keymaster_error_t)extract_final_input(in_data, &input, &signature);
    if (ret) {
        tloge("extract_final_input error\n");
        return ret;
    }
    tlogd("input size=%u and sig size=%u\n", input.data_length, signature.data_length);
    if ((input.data_addr != NULL) && (input.data_length > 0)) {
        tlogd("append finish input data to keynode data\n");
        bool condition = (((key_node->digest == KM_DIGEST_NONE) || (key_node->purpose == KM_PURPOSE_ENCRYPT) ||
            (key_node->purpose == KM_PURPOSE_DECRYPT)) && key_node->algorithm == KM_ALGORITHM_RSA);
        if (condition) {
            if (check_operation_rsa_update(key_node, input.data_length) != KM_ERROR_OK) {
                tloge("check_operation_rsa_update failed");
                return KM_ERROR_INVALID_INPUT_LENGTH;
            }
        }
        ret = asymmetric_update(key_node, input.data_addr, input.data_length);
        if (ret != KM_ERROR_OK)
            return ret;
    }
    in_data->data_addr = signature.data_addr;
    in_data->data_length = signature.data_length;
    if ((key_node->algorithm == KM_ALGORITHM_AES) && (key_node->block_mode == KM_MODE_CTR))
        in_data->data_length = input.data_length;
    return ret;
}


keymaster_error_t alloc_data_buff_for_operation_symmetric_begin(key_auth *key_node, uint32_t data_size)
{
    key_node->data = TEE_Malloc(data_size, 0);
    if (key_node->data == NULL) {
        tloge("key_node->data malloc failed\n");
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    key_node->data_size = 0;

    return KM_ERROR_OK;
}

static keymaster_error_t proc_symmetric_operation_finish(key_auth *key_node,
                                                         const keymaster_key_param_set_t *params_enforced,
                                                         uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                                         uint32_t *out_size, int force)
{
    bool aes_gcm_condition = ((key_node->algorithm == KM_ALGORITHM_AES) && (key_node->block_mode == KM_MODE_GCM) &&
        (!force));
    if (aes_gcm_condition)
        return proc_aes_gcm_with_no_force_for_operation_finish(key_node, params_enforced, out_data, out_size);
    else
        return operation_symmetric_finish(key_node, in_data, in_size, out_data, out_size, force);
}

static keymaster_error_t proc_all_algorithm_for_operation_finish(key_auth *key_node,
                                                                 const keymaster_key_param_set_t *params_enforced,
                                                                 uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                                                 uint32_t *out_size, int force)
{
    if (key_node->algorithm == KM_ALGORITHM_RSA)
        /* if in_data is not null, we need add the data to key_node->data */
        return proc_rsa_operation_finish(key_node, in_data, in_size, out_data, out_size, force);
    else if (key_node->algorithm == KM_ALGORITHM_EC)
        return operation_ec_finish(key_node, in_data, in_size, out_data, out_size);
    else if ((key_node->algorithm == KM_ALGORITHM_AES) || (key_node->algorithm == KM_ALGORITHM_HMAC) ||
             (key_node->algorithm == KM_ALGORITHM_TRIPLE_DES))
        return proc_symmetric_operation_finish(key_node, params_enforced, in_data, in_size, out_data, out_size, force);
    else
        return KM_ERROR_UNSUPPORTED_ALGORITHM;
}

keymaster_error_t operation_finish(uint64_t operation_handle, const keymaster_key_param_set_t *params_enforced,
                                   keymaster_blob_t *in_data, keymaster_blob_t *out_data, int force)
{
    keymaster_error_t ret;
    key_auth *key_node = NULL;
    TEE_Result find;
    bool con = (in_data == NULL || out_data == NULL);
    if (con) {
        tloge("null pointers\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }

    find = get_auth_node(operation_handle, &key_node);
    con  = (find != TEE_SUCCESS || key_node == NULL);
    if (con) {
        tloge("can't find auth node\n");
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    }
    tlogd("key_node->algorithm is %d, key_node->purpose is %d\n", key_node->algorithm, key_node->purpose);
    con = (in_data != NULL && (in_data->data_addr != NULL) && (in_data->data_length > 0));
    if (con) {
        ret = preproc_operation_finish(key_node, in_data);
        if (ret != KM_ERROR_OK) {
            tloge("preproc operation finish failed\n");
            return ret;
        }
    }
    ret = proc_all_algorithm_for_operation_finish(key_node, params_enforced, in_data->data_addr, in_data->data_length,
        out_data->data_addr, &(out_data->data_length), force);
    con = ((force == 0) && (ret != KM_ERROR_OK));
    if (con)
        tloge("algorithm %d ,mode %d finish failed, ret is %x\n", key_node->algorithm, key_node->block_mode, ret);
    return ret;
}

static keymaster_error_t do_hash_finish_for_sign_verify(key_auth *key_node, TEE_OperationHandle digest_contextid_ptr,
    uint8_t *hash_result_buff)
{
    TEE_Result rc;
    size_t out_size = HASH_BLOCK_SIZE_64;
    rc = TEE_DigestDoFinal(digest_contextid_ptr, NULL, 0, (uint8_t *)hash_result_buff, &out_size);
    if (rc != TEE_SUCCESS) {
        tloge("TEE_DigestDoFinal failed ret is 0x%x\n", rc);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    key_node->data = hash_result_buff;
    if (hash_mode_to_size_bits(key_node->digest, &key_node->data_size) != KM_ERROR_OK) {
        tloge("get hash size bits failed\n");
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    key_node->data_size = eight_align_up(key_node->data_size) / BITS_ONE_BYTE;
    return KM_ERROR_OK;
}
keymaster_error_t do_hash_for_sign_verify(key_auth *key_node)
{
    keymaster_error_t ret;
    TEE_Result result;
    uint8_t *hash_result_buff = (uint8_t *)TEE_Malloc(HASH_BLOCK_SIZE_64, 0);
    if (hash_result_buff == NULL) {
        tloge("malloc is failed\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    TEE_OperationHandle digest_contextid_ptr = (TEE_OperationHandle)key_node->aad_data;
    if (digest_contextid_ptr == NULL) {
        uint32_t algorithm = keymaster_get_digest_hash(key_node->digest);
        if (algorithm == 0) {
            tloge("key node digest is not right.\n");
            TEE_Free(hash_result_buff);
            hash_result_buff = NULL;
            return KM_ERROR_UNKNOWN_ERROR;
        }
        result = TEE_AllocateOperation(&digest_contextid_ptr, algorithm, TEE_MODE_DIGEST, 0);
        if (result != TEE_SUCCESS) {
            tloge("TEE_AllocateOperation failed\n");
            TEE_Free(hash_result_buff);
            hash_result_buff = NULL;
            return KM_ERROR_UNKNOWN_ERROR;
        }
        key_node->aad_data = (uint8_t *)digest_contextid_ptr;
    }
    if (key_node->data != NULL)
        do_hash_update_for_sign_verify(key_node, digest_contextid_ptr);
    ret = do_hash_finish_for_sign_verify(key_node, digest_contextid_ptr, hash_result_buff);
    if (ret != KM_ERROR_OK) {
        tloge("do_hash_update_for_sign_verify failed\n");
        TEE_Free(hash_result_buff);
        hash_result_buff = NULL;
    }
    if (digest_contextid_ptr != NULL)
        TEE_FreeOperation(digest_contextid_ptr);
    key_node->aad_data = NULL;
    return ret;
}
static void get_algorithm_params(key_auth *key_node, const keymaster_key_param_set_t *params_enforced)
{
    int ret;
    key_node->digest = KM_DIGEST_NONE;
    key_node->padding = KM_PAD_NONE;
    key_node->block_mode = KM_MODE_CBC;
    ret = get_key_param(KM_TAG_DIGEST, &(key_node->digest), params_enforced);
    if (ret != 0)
        tlogd("get_key_param of KM_TAG_DIGEST failed\n");
    ret = get_key_param(KM_TAG_PADDING, &(key_node->padding), params_enforced);
    if (ret != 0)
        tlogd("%d get_key_param of KM_TAG_PADDING failed\n", key_node->algorithm);
    ret = get_key_param(KM_TAG_BLOCK_MODE, &(key_node->block_mode), params_enforced);
    if (ret != 0)
        tlogd("%d get_key_param of KM_TAG_BLOCK_MODE failed\n", key_node->algorithm);
    if (key_node->block_mode == KM_MODE_ECB)
        tlogw("Warning: An insecure block mode is being used: ECB\n");
    if (key_node->digest == KM_DIGEST_MD5 || key_node->digest == KM_DIGEST_SHA1) {
        tlogw("Warning: An insecure digest for hmac is being used: %s, digest id %d\n",
            (key_node->digest == KM_DIGEST_MD5) ? "MD5" : "SHA1", key_node->digest);
    }
    return;
}
static keymaster_error_t set_check_aes_params(const keymaster_key_param_set_t *params_enforced,
                                              const keymaster_key_param_set_t *hw_enforced, key_auth *key_node)
{
    uint32_t min_tag_len = 0;
    keymaster_error_t ret;
    if (get_key_param(KM_TAG_PADDING, &(key_node->padding), params_enforced) != 0) {
        tloge("AES get_key_param of KM_TAG_PADDING failed\n");
        return KM_ERROR_INCOMPATIBLE_PADDING_MODE;
    }
    if (get_key_param(KM_TAG_BLOCK_MODE, &(key_node->block_mode), params_enforced) != 0) {
        tloge("AES get_key_param of KM_TAG_BLOCK_MODE failed\n");
        return KM_ERROR_INCOMPATIBLE_BLOCK_MODE;
    }
    bool condition = ((key_node->block_mode != KM_MODE_ECB && key_node->block_mode != KM_MODE_CBC) &&
        key_node->padding == KM_PAD_PKCS7);
    if (condition) {
        tloge("0x%x mod do not support padding 0x%x\n", key_node->block_mode, key_node->padding);
        return KM_ERROR_INCOMPATIBLE_BLOCK_MODE;
    }
    ret = check_gcm_tag_len(key_node->block_mode, params_enforced, hw_enforced, &(key_node->tag_len_bit),
        &min_tag_len);
    if (ret != KM_ERROR_OK) {
        tloge("check_gcm_tag_len is failed, ret=0x%x\n", ret);
        return ret;
    }
    if (is_key_param_suport(KM_TAG_BLOCK_MODE, (void *)&(key_node->block_mode), hw_enforced) == 0) {
        tloge("do not support block mode 0x%x\n", key_node->block_mode);
        return KM_ERROR_INCOMPATIBLE_BLOCK_MODE;
    }
    if (is_key_param_suport(KM_TAG_PADDING, (void *)&(key_node->padding), hw_enforced) == 0) {
        tloge("do not support padding 0x%x\n", key_node->padding);
        return KM_ERROR_INCOMPATIBLE_PADDING_MODE;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t set_check_aes_param(const keymaster_key_param_set_t *params_enforced,
    const keymaster_key_param_set_t *hw_enforced, key_auth *key_node)
{
    bool check_fail = (params_enforced == NULL || hw_enforced == NULL || key_node == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    keymaster_error_t ret = set_check_aes_params(params_enforced, hw_enforced, key_node);
    if (ret != KM_ERROR_OK)
        tloge("set check aes params failed\n");
    return ret;
}

static keymaster_error_t check_3des_param(const keymaster_key_param_set_t *hw_enforced, const key_auth *key_node)
{
    bool check_fail = (hw_enforced == NULL || key_node == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (!is_key_param_suport(KM_TAG_BLOCK_MODE, (void *)&(key_node->block_mode), hw_enforced)) {
        tloge("do not support block mode 0x%x\n", key_node->block_mode);
        return KM_ERROR_INCOMPATIBLE_BLOCK_MODE;
    }
    if (!is_key_param_suport(KM_TAG_PADDING, (void *)&(key_node->padding), hw_enforced)) {
        tloge("do not support padding 0x%x\n", key_node->padding);
        return KM_ERROR_INCOMPATIBLE_PADDING_MODE;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t check_hmac_param(const keymaster_key_param_set_t *params_enforced,
    const keymaster_key_param_set_t *hw_enforced, key_auth *key_node)
{
    bool check_fail = (hw_enforced == NULL || key_node == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    keymaster_error_t ret;
    if (!is_key_param_suport(KM_TAG_DIGEST, (void *)&(key_node->digest), hw_enforced)) {
        tloge("donot support digest = 0x%x\n", key_node->digest);
        return KM_ERROR_INCOMPATIBLE_DIGEST;
    }
    ret = check_hmc_tag_len(key_node, params_enforced, hw_enforced, &(key_node->tag_len_bit));
    if (ret != KM_ERROR_OK)
        tloge("check_hmc_tag_len is failed, ret=0x%x\n", ret);
    return ret;
}

static keymaster_error_t set_check_symmetric_params(const keymaster_key_param_set_t *params_enforced,
    const keymaster_key_param_set_t *hw_enforced, key_auth *key_node)
{
    keymaster_error_t ret;
    bool check_fail = ((key_node->algorithm == KM_ALGORITHM_AES || key_node->algorithm == KM_ALGORITHM_TRIPLE_DES) &&
        (key_node->purpose != KM_PURPOSE_ENCRYPT && key_node->purpose != KM_PURPOSE_DECRYPT));
    if (check_fail) {
        tloge("bad purpose %d\n", key_node->purpose);
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }
    if (key_node->algorithm == KM_ALGORITHM_AES)
        ret = set_check_aes_param(params_enforced, hw_enforced, key_node);
    else if (key_node->algorithm == KM_ALGORITHM_TRIPLE_DES)
        ret = check_3des_param(hw_enforced, key_node);
    else if (key_node->algorithm == KM_ALGORITHM_HMAC)
        ret = check_hmac_param(params_enforced, hw_enforced, key_node);

    if (get_key_param(KM_TAG_KEY_SIZE, &(key_node->key1_size), hw_enforced) != 0) {
        tloge("get_key_param of key size failed\n");
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    tlogd("get key_size from key blob %u\n", key_node->key1_size);
    return ret;
}
static bool need_iv(keymaster_block_mode_t block_mode)
{
    bool need_iv = (block_mode == KM_MODE_CBC || block_mode == KM_MODE_CTR || block_mode == KM_MODE_GCM);
    return need_iv;
}
static keymaster_error_t get_iv_gen_params(const keymaster_key_param_set_t *params_enforced,
                                           const key_auth *key_node, keymaster_blob_t *iv, int *iv_gen)
{
    int ret = get_key_param(KM_TAG_NONCE, iv, params_enforced);
    if (ret == -1) {
        tlogd("there is no iv in params set\n");
        if (key_node->purpose == KM_PURPOSE_DECRYPT) {
            tloge("decrypt need IV from in_params\n");
            return KM_ERROR_INCOMPATIBLE_PURPOSE;
        }
        *iv_gen = 1;
    }
    /* find IV in params then check it */
    if (!(*iv_gen) && key_node->algorithm == KM_ALGORITHM_AES) {
        if (key_node->block_mode != KM_MODE_GCM && iv->data_length != AES_BLOCK_SIZE_IN_BYTES) {
            tloge("invalid IV size %u for block_mode %u\n", iv->data_length, key_node->block_mode);
            return KM_ERROR_INVALID_NONCE;
        }
        if (key_node->block_mode == KM_MODE_GCM && iv->data_length != g_gcm_nonce_size) {
            tloge("invalid IV size %u for KM_MODE_GCM\n", iv->data_length);
            return KM_ERROR_INVALID_NONCE;
        }
    }

    if (!(*iv_gen) && key_node->algorithm == KM_ALGORITHM_TRIPLE_DES) {
        if (iv->data_length != DES3_IV_LEN) {
            tloge("invalid IV size %u for KM_ALGORITHM_TRIPLE_DES\n", iv->data_length);
            return KM_ERROR_INVALID_NONCE;
        }
    }
    return KM_ERROR_OK;
}

static void get_iv_len(keymaster_algorithm_t algorithm, uint32_t block_mode, uint32_t *temp_iv_len)
{
    bool iv_condition = (algorithm == KM_ALGORITHM_AES && block_mode == KM_MODE_GCM);
    if (iv_condition)
        *temp_iv_len = IV_LEN_TWELVE;
    iv_condition = (algorithm == KM_ALGORITHM_AES && block_mode != KM_MODE_GCM);
    if (iv_condition)
        *temp_iv_len = IV_LEN;
    if (algorithm == KM_ALGORITHM_TRIPLE_DES)
        *temp_iv_len = DES3_IV_LEN;
}

static keymaster_error_t generate_iv(uint8_t *iv_buff, uint32_t iv_len, keymaster_blob_t *iv)
{
    TEE_GenerateRandom(iv_buff, iv_len);
    uint32_t i;
    uint32_t j = 0;
    for (i = 0; i < iv_len; i++) {
        if (iv_buff[i] == 0)
            j++;
    }
    if (j == iv_len) {
        tloge("generate iv random failed\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    iv->data_addr = iv_buff;
    iv->data_length = iv_len;
    return KM_ERROR_OK;
}
static keymaster_error_t process_encrypt_params(key_auth *key_node, int32_t iv_gen, keymaster_blob_t *new_iv,
    keymaster_blob_t *iv, TEE_Param *params)
{
    errno_t rc;
    uint32_t temp_iv_len = 0;
    get_iv_len(key_node->algorithm, key_node->block_mode, &temp_iv_len);
    if (temp_iv_len > new_iv->data_length) {
        tloge("invalid temp iv length %u, buff len %u\n", temp_iv_len, new_iv->data_length);
        return KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
    }
    if ((iv_gen != 0) && (generate_iv(new_iv->data_addr, temp_iv_len, iv) != KM_ERROR_OK)) {
        tloge("generate iv failed\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    uint32_t out_size = 0;
    uint8_t *p1 = (uint8_t *)params[PARAM_TWO].memref.buffer;
    if (sizeof(keymaster_key_param_t) + sizeof(uint32_t) + temp_iv_len > params[PARAM_TWO].memref.size) {
        tloge("invalid params buffer size\n");
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }
    *(uint32_t *)p1 = 1;
    out_size += sizeof(uint32_t);
    p1 += sizeof(uint32_t);
    keymaster_key_param_t *temp_params = (keymaster_key_param_t *)p1;
    temp_params[PARAM_ZERO].tag        = KM_TAG_NONCE;
    temp_params[PARAM_ZERO].blob.data_offset = 0;
    temp_params[PARAM_ZERO].blob.data_length = temp_iv_len;
    out_size += sizeof(keymaster_key_param_t);
    p1 += sizeof(keymaster_key_param_t);
    if (iv_gen)
        rc = memcpy_s(p1, temp_iv_len, new_iv->data_addr, temp_iv_len);
    else
        rc = memcpy_s(p1, temp_iv_len, iv->data_addr, temp_iv_len);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        return KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
    }
    out_size += temp_iv_len;
    params[PARAM_TWO].memref.size = out_size;
    return KM_ERROR_OK;
}
static keymaster_error_t prepare_iv(key_auth *key_node, keymaster_blob_t *new_iv,
    const keymaster_key_param_set_t *params_enforced, keymaster_blob_t *iv, TEE_Param *params)
{
    bool param_check_fail = (key_node == NULL || new_iv == NULL || new_iv->data_addr == NULL ||
        params_enforced == NULL || iv == NULL || params == NULL);
    if (param_check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (need_iv(key_node->block_mode) && (key_node->algorithm == KM_ALGORITHM_AES ||
        key_node->algorithm == KM_ALGORITHM_TRIPLE_DES)) {
        int32_t iv_gen = 0;
        keymaster_error_t ret = get_iv_gen_params(params_enforced, key_node, iv, &iv_gen);
        if (ret != KM_ERROR_OK) {
            tloge("get_iv_gen_params is failed,ret=0x%x\n", ret);
            return ret;
        }

        if (key_node->purpose == KM_PURPOSE_ENCRYPT) {
            ret = process_encrypt_params(key_node, iv_gen, new_iv, iv, params);
            if (ret != KM_ERROR_OK) {
                tloge("process_encrypt_params failed.\n");
                return ret;
            }
        }
    }
    return KM_ERROR_OK;
}
static keymaster_error_t km_aes_des_hmac_begin(const keymaster_key_param_set_t *params_enforced,
    keyblob_head *key_blob, key_auth *key_node, const struct kb_crypto_factors *factors, TEE_Param *params)
{
    keymaster_blob_t iv = { NULL, 0 };
    uint8_t temp_iv[IV_LEN] = { 0 };
    keymaster_blob_t new_iv = { temp_iv, IV_LEN };
    uint8_t *keymaterial = (uint8_t *)key_blob + key_blob->keymaterial_offset;
    get_algorithm_params(key_node, params_enforced);
    const keymaster_key_param_set_t *hw_enforced =
        (keymaster_key_param_set_t *)((uint8_t *)key_blob + key_blob->hw_enforced_offset);
    keymaster_error_t ret = set_check_symmetric_params(params_enforced, hw_enforced, key_node);
    if (ret != KM_ERROR_OK) {
        tloge("set and check symmetric alg params failed, ret=0x%x\n", ret);
        return ret;
    }
    ret = prepare_iv(key_node, &new_iv, params_enforced, &iv, params);
    if (ret != KM_ERROR_OK) {
        tloge("prepare iv failed\n");
        return ret;
    }
    keymaster_blob_t key = { NULL, ((struct keymaterial_symmetric_header *)keymaterial)->key_buff_len };
    key.data_addr = (uint8_t *)TEE_Malloc(key.data_length, TEE_MALLOC_FILL_ZERO);
    if (key.data_addr == NULL) {
        tloge("alloc symetric_key failed, key buff len =%u\n", key.data_length);
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    if (parser_symmetric_keymaterial(keymaterial, key.data_addr, key_node->key1_size, key_blob->version, factors) !=
        TEE_SUCCESS) {
        tloge("parser symmetric keymaterial failed\n");
        free_blob(&key);
        return KM_ERROR_VERIFICATION_FAILED;
    }

    ret = operation_symmetric_begin(key_node, &key, &iv);
    erase_free_blob(&key);
    if (ret != KM_ERROR_OK)
        tloge("operation begin failed\n");
    return ret;
}
static uint32_t judge_algorithm_type(keymaster_algorithm_t algorithm)
{
    bool algorithm_check = (algorithm == KM_ALGORITHM_AES || algorithm == KM_ALGORITHM_HMAC ||
        algorithm == KM_ALGORITHM_TRIPLE_DES);
    uint32_t ret = (algorithm_check ? 1 : 0);
    return ret;
}
keymaster_error_t km_algorithm_begin(const keymaster_key_param_set_t *params_enforced, keyblob_head *key_blob,
    key_auth *key_node, const struct kb_crypto_factors *factors, TEE_Param *params)
{
    if (key_node->algorithm == KM_ALGORITHM_RSA) {
        return km_rsa_begin(params_enforced, key_blob, key_node, factors);
    } else if (key_node->algorithm == KM_ALGORITHM_EC) {
        return km_ec_begin(params_enforced, key_blob, key_node, factors);
    } else if (judge_algorithm_type(key_node->algorithm)) {
        return km_aes_des_hmac_begin(params_enforced, key_blob, key_node, factors, params);
    } else {
        tloge("unsupported algorithm %d\n", key_node->algorithm);
        return (keymaster_error_t)TEE_ERROR_NOT_SUPPORTED;
    }
}

static TEE_Result allocate_key_object(keymaster_algorithm_t algorithm, keymaster_digest_t digest, uint32_t key_size,
    TEE_ObjectHandle *key_obj)
{
    /* Notice: this function will allocate memory for key_obj, it should be freed by its declared function */
    if (key_obj == NULL) {
        tloge("null pointer");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (*key_obj != TEE_HANDLE_NULL) {
        tloge("this key object is inited\n");
        TEE_FreeTransientObject(*key_obj);
        *key_obj = TEE_HANDLE_NULL;
    }
    uint32_t object_type;
    TEE_Result ret = get_key_obj_type(algorithm, digest, &object_type);
    if (ret != TEE_SUCCESS) {
        tloge("get key object type failed, algorithm %d, digest %u\n", algorithm, digest);
        return ret;
    }
    ret = TEE_AllocateTransientObject(object_type, key_size, key_obj);
    if (ret != TEE_SUCCESS)
        tloge("allocate transient object failed\n");
    return ret;
}

TEE_Result init_key_obj(keymaster_algorithm_t km_alg, keymaster_digest_t digest, uint32_t key_size_bits,
    TEE_ObjectHandle *obj_handle, keymaster_blob_t *key)
{
    bool check_fail = (obj_handle == NULL || key == NULL || key->data_addr == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (*obj_handle != TEE_HANDLE_NULL) {
        tloge("this obj handle is inited\n");
        TEE_FreeTransientObject(*obj_handle);
        *obj_handle = TEE_HANDLE_NULL;
    }

    TEE_Result result = allocate_key_object(km_alg, digest, key_size_bits, obj_handle);
    if (result != TEE_SUCCESS) {
        tloge("allocate key object failed\n");
        return result;
    }
    result = gp_buffer_to_key_obj(key->data_addr, key->data_length, *obj_handle);
    if (result != TEE_SUCCESS)
        tloge("parse buffer to key object failed\n");
    (void)memset_s(key->data_addr, key->data_length, 0, key->data_length);
    return result;
}

TEE_Result init_key_operation(TEE_OperationHandle *op_handle, uint32_t alg, uint32_t gp_purpose, uint32_t key_size_bits,
    const TEE_ObjectHandle *key_obj)
{
    TEE_Result ret;
    bool check_fail = (op_handle == NULL || key_obj == NULL);
    if (check_fail) {
        tloge("null pointers\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (*op_handle != TEE_HANDLE_NULL) {
        tloge("this op handle is inited\n");
        TEE_FreeOperation(*op_handle);
        *op_handle = TEE_HANDLE_NULL;
    }
    ret = TEE_AllocateOperation(op_handle, alg, gp_purpose, key_size_bits);
    if (ret != TEE_SUCCESS) {
        tloge("alloc crypto operation failed, ret=0x%x\n", ret);
        return ret;
    }
    ret = TEE_SetOperationKey(*op_handle, *key_obj);
    if (ret != TEE_SUCCESS)
        tloge("set OperationKey failed, ret=0x%x\n", ret);
    return ret;
}

int32_t asymmetric_hash_update(key_auth *key_node, uint8_t *datain_ptr, uint32_t data_size)
{
    int32_t ret;
    TEE_OperationHandle ctx = TEE_HANDLE_NULL;
    TEE_Result result;
    uint32_t hash_len;
    uint32_t data_update_len = 0;
    uint8_t *data_update = NULL;
    uint32_t type;
    if (key_node == NULL) {
        tloge("key_node is null\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    ret = get_hash_block_size(key_node->digest, &hash_len);
    if (ret == -1) {
        tloge("get_hash_block_size failed\n");
        return -1;
    }
    type = keymaster_get_digest_hash(key_node->digest);
    if (type == 0) {
        tloge("get_digest_hash failed\n");
        return -1;
    }
    if (key_node->aad_data == NULL) {
        result = TEE_AllocateOperation(&ctx, type, TEE_MODE_DIGEST, 0);
        if (result != TEE_SUCCESS) {
            tloge("TEE_AllocateOperation failed, ret is 0x%x\n", result);
            ret = -1;
            goto error_exit;
        }
    } else {
        ctx = (TEE_OperationHandle)key_node->aad_data;
    }
    ret = proc_asymmetric_hash_update(key_node, ctx, &data_update, &data_update_len, hash_len, datain_ptr, data_size);
    if (ret == -1) {
        tloge("proc_asymmetric_hash_update failed\n");
        goto error_exit;
    }
    if (data_update != NULL && data_update_len != 0)
        TEE_DigestUpdate(ctx, data_update, data_update_len);
    key_node->aad_data = (uint8_t *)ctx;
    return 0;
error_exit:
    if (ctx != TEE_HANDLE_NULL)
        TEE_FreeOperation(ctx);
    ctx = TEE_HANDLE_NULL;
    key_node->aad_data = NULL;
    return ret;
}

int32_t get_kb_crypto_factors(const keymaster_key_param_set_t *params_blob,
    const keymaster_key_param_set_t *params_input, uint32_t version, const keymaster_blob_t *app_id,
    struct kb_crypto_factors *factors)
{
    if (params_blob == NULL || factors == NULL) {
        tloge("get crypto factors: null pointer");
        return -1;
    }
    if (app_id != NULL)
        factors->app_id = *app_id;
    else
        get_application_id(&(factors->app_id), params_input);

#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    if (version == VERSION_340 || version == VERSION_540 ||
        version == VERSION_341 || version == VERSION_541) {
        if (get_key_param(KM_TAG_HW_ENHANCED_KEY_APPID, &(factors->app_id), params_input) != 0) {
            tloge("need enhanced appid, but not provide");
            return -1;
        }
    }

    if (version == VERSION_341 || version == VERSION_541) {
        if (get_inse_factor(params_blob, &(factors->inse_factor)) != TEE_SUCCESS) {
            tloge("need inse factor, but not provide");
            return -1;
        }
    } else {
        factors->inse_factor.data_addr = NULL;
        factors->inse_factor.data_length = 0;
    }
#else
    (void)version;
#endif
    return 0;
}
