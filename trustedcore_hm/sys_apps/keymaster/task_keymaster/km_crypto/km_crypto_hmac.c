/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster hmac cipher functions implementation
 * Create: 2020-11-09
 */

#include "securec.h"
#include "keymaster_defs.h"
#include "km_types.h"
#include "tee_crypto_api.h"
#include "km_keynode.h"
#include "km_tag_operation.h"
#include "km_common.h"
#include "km_crypto.h"
#include "km_crypto_hmac.h"
#include "km_crypto_adaptor.h"

uint32_t hash_block_size(keymaster_digest_t digest)
{
    bool hash_block_check = ((digest == KM_DIGEST_SHA1) || (digest == KM_DIGEST_SHA_2_224) ||
        (digest == KM_DIGEST_SHA_2_256));
    if (hash_block_check)
        return HASH_BLOCK_SIZE_64;
    else
        return HASH_BLOCK_SIZE_128;
}

static keymaster_error_t proc_large_size_km_hmac_update(key_auth *key_node, const uint8_t *in_data, uint32_t in_size,
                                                        uint32_t block_size)
{
    bool check_fail = (block_size == 0 || key_node == NULL || key_node->data == NULL ||
                       key_node->crypto_ctxt == NULL);
    if (check_fail) {
        tloge("invalid parameters\n");
        return KM_ERROR_INVALID_ARGUMENT;
    }
    uint8_t *tmp_buff  = NULL;
    uint32_t in_offset = 0;
    errno_t rc;
    uint32_t reserve_size = (key_node->data_size + in_size) % block_size;
    uint32_t update_size  = (key_node->data_size + in_size) - reserve_size;
    TEE_OperationHandle hmac_ops = (TEE_OperationHandle)key_node->crypto_ctxt;
    if (key_node->data_size != 0) {
        in_offset = block_size - key_node->data_size;
        tmp_buff = (uint8_t *)TEE_Malloc(block_size, 0);
        if (tmp_buff == NULL) {
            tloge("alloc hmac tmp buff failed\n");
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        rc = memcpy_s(tmp_buff, block_size, key_node->data, key_node->data_size);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            TEE_Free(tmp_buff);
            tmp_buff = NULL;
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        rc = memcpy_s(tmp_buff + key_node->data_size, in_offset, in_data, in_offset);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            TEE_Free(tmp_buff);
            tmp_buff = NULL;
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        TEE_MACUpdate(hmac_ops, tmp_buff, block_size);
        TEE_Free(tmp_buff);
        tmp_buff = NULL;
    }
    TEE_MACUpdate(hmac_ops, in_data + in_offset, update_size - (key_node->data_size + in_offset));
    if (reserve_size > 0) {
        rc = memcpy_s(key_node->data, block_size, in_data + (update_size - key_node->data_size), reserve_size);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
    }
    key_node->data_size = reserve_size;
    return KM_ERROR_OK;
}

keymaster_error_t km_hmac_update(key_auth *key_node, const uint8_t *in_data, uint32_t in_size)
{
    if ((key_node == NULL) || (in_data == NULL)) {
        tloge("key_node or in_data is null\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    errno_t rc;
    keymaster_error_t ret;
    uint32_t block_size   = hash_block_size(key_node->digest);
    tlogd("hash algo=%d, blocksize=%u\n", key_node->digest, block_size);
    if (key_node->data_size > (UINT32_MAX - in_size)) {
        tloge("in_data size invalid:%u\n", in_size);
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }
    if ((key_node->data_size + in_size) < block_size) {
        rc = memcpy_s(key_node->data + key_node->data_size, block_size - key_node->data_size, in_data, in_size);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        key_node->data_size += in_size;
    } else {
        ret = proc_large_size_km_hmac_update(key_node, in_data, in_size, block_size);
        if (ret != KM_ERROR_OK) {
            tloge("proc_large_size_km_hmac_update failed,ret=0x%x\n", ret);
            return ret;
        }
    }
    tlogd("TEE_MACUpdate success\n");
    return KM_ERROR_OK;
}

static keymaster_error_t hmac_sign_or_verify(keymaster_purpose_t purpose, uint32_t *out_size, uint32_t in_size,
                                             const uint8_t *in_data, uint8_t *out_data, const uint8_t *data_tmp)
{
    errno_t rc;
    if (purpose == KM_PURPOSE_SIGN) {
        rc = memcpy_s(out_data, *out_size, data_tmp, *out_size);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        return KM_ERROR_OK;
    } else if (purpose == KM_PURPOSE_VERIFY) {
        if ((in_size != *out_size) || TEE_MemCompare(in_data, data_tmp, *out_size)) {
            tloge("HMAC compare failed\n");
            *out_size = 0;
            return KM_ERROR_VERIFICATION_FAILED;
        } else {
            *out_size = 0;
            return KM_ERROR_OK;
        }
    } else {
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }
}

static keymaster_error_t check_params_res(uint32_t *out_size, TEE_Result result)
{
    if (out_size == NULL) {
        tloge("out_size is null\n");
        return (keymaster_error_t)TEE_ERROR_BAD_PARAMETERS;
    }
    if (result != TEE_SUCCESS) {
        tloge("HMAC finish failed\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t get_need_out_size(const key_auth *key_node, uint32_t *out_size, uint32_t *need_out_size)
{
    keymaster_digest_t digest   = key_node->digest;
    if (get_real_hash_len(digest, need_out_size)) {
        tloge("invalied digest 0x%x\n", digest);
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    if (key_node->tag_len_bit > 0) {
        tlogd("set mac len as min len\n");
        *need_out_size = key_node->tag_len_bit / BITS_ONE_BYTE;
    }

    if (*out_size < *need_out_size) {
        tloge("output buffer too small\n");
        return (keymaster_error_t)TEE_ERROR_BAD_PARAMETERS;
    }
    *out_size = *need_out_size;
    return KM_ERROR_OK;
}
keymaster_error_t hmac_finish(const key_auth *key_node, const uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                              uint32_t *out_size, int force)
{
    if ((key_node == NULL) || (out_data == NULL) || (out_size == NULL)) {
        tloge("key_node or out_data or out_size is null\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    TEE_Result result;
    keymaster_error_t kerror = KM_ERROR_OK;
    uint8_t *data_tmp = NULL;
    data_tmp = (uint8_t *)TEE_Malloc(*out_size, 0);
    if (data_tmp == NULL) {
        tloge("failed to mallco for temp_buffer, len is %u\n", *out_size);
        return KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
    }
    TEE_OperationHandle hmac_ops = (TEE_OperationHandle)key_node->crypto_ctxt;
    keymaster_purpose_t purpose = key_node->purpose;
    size_t true_out_size       =  *out_size;
    uint32_t need_out_size       =  64;
    if (key_node->data_size != 0)
        TEE_MACUpdate(hmac_ops, key_node->data, key_node->data_size);
    result = TEE_MACComputeFinal(hmac_ops, (void *)NULL, (size_t)0, (void *)data_tmp, &true_out_size);
    if (force == 0) {
        kerror = check_params_res(out_size, result);
        if (kerror != KM_ERROR_OK) {
            tloge("check params or result failed\n");
            goto hmac_finish_error;
        }
        kerror = get_need_out_size(key_node, out_size, &need_out_size);
        if (kerror != KM_ERROR_OK) {
            tloge("get need out size failed\n");
            goto hmac_finish_error;
        }
        kerror = hmac_sign_or_verify(purpose, out_size, in_size, in_data, out_data, data_tmp);
        if (kerror != KM_ERROR_OK) {
            tloge("hmac sign or verify failed\n");
            goto hmac_finish_error;
        }
    }
hmac_finish_error:
    TEE_Free(data_tmp);
    data_tmp = NULL;
    return kerror;
}

keymaster_error_t km_hmac_init(keymaster_blob_t *key, key_auth *key_node)
{
    TEE_Result ret;
    keymaster_error_t err;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle key_object = TEE_HANDLE_NULL;
    uint32_t algorithm = TEE_TYPE_HMAC_SHA256;
    bool check_fail = (key_node == NULL || key == NULL || key->data_addr == NULL);
    if (check_fail) {
        tloge("parameter is null\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    err = get_hmac_algorithm(key_node->digest, &algorithm);
    if (err != KM_ERROR_OK) {
        tloge("Get algorithm from hmac digest failed\n");
        return err;
    }

    ret = init_key_obj(key_node->algorithm, key_node->digest, key_node->key1_size, &key_object, key);
    if (ret != TEE_SUCCESS) {
        tloge("init key object failed, ret 0x%x\n", ret);
        err = KM_ERROR_UNKNOWN_ERROR;
        goto release;
    }
    ret = init_key_operation(&op_handle, algorithm, TEE_MODE_MAC, key_node->key1_size, &key_object);
    if (ret != TEE_SUCCESS) {
        tloge("alloc crypto operation failed, result=0x%x\n", ret);
        err = KM_ERROR_UNKNOWN_ERROR;
        goto op_error;
    }
    key_node->crypto_ctxt = (void *)op_handle;

    TEE_MACInit(key_node->crypto_ctxt, NULL, 0);
    tlogd("TEE_MACInit success\n");
    goto release;
op_error:
    TEE_FreeOperation(op_handle);
    op_handle = TEE_HANDLE_NULL;
release:
    (void)memset_s(key->data_addr, key->data_length, 0, key->data_length);
    TEE_FreeTransientObject(key_object);
    key_object = TEE_HANDLE_NULL;
    return err;
}

keymaster_error_t km_hmac_begin(key_auth *key_node, keymaster_blob_t *key)
{
    keymaster_error_t ret;
    /* for save block un-align data */
    if (key_node != NULL && key_node->data == NULL) {
        ret = alloc_data_buff_for_operation_symmetric_begin(key_node, hash_block_size(key_node->digest));
        if (ret != KM_ERROR_OK) {
            tloge("alloc_data_buff_for_operation_symmetric_begin failed");
            return ret;
        }
    }

    return km_hmac_init(key, key_node);
}

