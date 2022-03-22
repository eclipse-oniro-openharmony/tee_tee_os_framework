/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster aes cipher functions implementation
 * Create: 2020-11-09
 */

#include "securec.h"
#include "keymaster_defs.h"
#include "km_types.h"
#include "tee_crypto_api.h"
#include "km_common.h"
#include "km_keynode.h"
#include "km_tag_operation.h"
#include "km_crypto.h"
#include "km_crypto_adaptor.h"
#include "km_crypto_check.h"
#define GCM_KEYSIZE_128   16
#define GCM_KEYSIZE_192   24
#define GCM_KEYSIZE_256   32

#define AES_MAX_KEY_SIZE 256
#define GCM_WORK_PAYLOAD_SIZE (64 * 1024)
static keymaster_error_t km_aes_init(key_auth *key_node, keymaster_blob_t *iv, keymaster_blob_t *key_obj_buff,
    TEE_OperationMode gp_purpose, uint32_t gp_alg)
{
    TEE_Result result;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle key_object = TEE_HANDLE_NULL;
    keymaster_error_t ret = KM_ERROR_OK;
    result = init_key_obj(key_node->algorithm, KM_DIGEST_NONE, key_node->key1_size, &key_object, key_obj_buff);
    if (result != TEE_SUCCESS) {
        tloge("init key object failed, ret 0x%x\n", result);
        ret = KM_ERROR_UNKNOWN_ERROR;
        goto release;
    }
    result = init_key_operation(&op_handle, gp_alg, gp_purpose, key_node->key1_size, &key_object);
    if (result != TEE_SUCCESS) {
        tloge("alloc crypto operation failed, result=0x%x\n", result);
        ret = KM_ERROR_UNKNOWN_ERROR;
        goto op_error;
    }
    key_node->crypto_ctxt = (void *)op_handle;
    if (gp_alg == TEE_ALG_AES_GCM) {
        tlogd("aes gcm init: tag_len_bit %u\n", key_node->tag_len_bit);
        result = TEE_AEInit((TEE_OperationHandle)key_node->crypto_ctxt, iv->data_addr, iv->data_length,
            key_node->tag_len_bit, 0, GCM_WORK_PAYLOAD_SIZE);
        if (result != TEE_SUCCESS) {
            tloge("TEE_AEInit failed, ret %x\n", result);
            ret = (keymaster_error_t)result;
            goto op_error;
        }
        tlogd("TEE_AEInit test pass\n");
    } else {
        TEE_CipherInit((TEE_OperationHandle)key_node->crypto_ctxt, iv->data_addr, iv->data_length);
        tlogd("TEE_CipherInit test pass\n");
    }
    goto release;
op_error:
    TEE_FreeOperation(op_handle);
    op_handle = TEE_HANDLE_NULL;
release:
    (void)memset_s(key_obj_buff->data_addr, key_obj_buff->data_length, 0, key_obj_buff->data_length);
    TEE_FreeTransientObject(key_object);
    key_object = TEE_HANDLE_NULL;
    return ret;
}

keymaster_error_t km_aes_begin(key_auth *key_node, keymaster_blob_t *iv, keymaster_blob_t *key)
{
    uint32_t algorithm = TEE_ALG_AES_CBC_NOPAD;
    TEE_OperationMode gp_purpose = TEE_MODE_ENCRYPT;
    bool check_fail = (key_node == NULL || key == NULL || key->data_addr == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (check_aes_keysize_bits(key_node->key1_size) != 0) {
        tloge("invalid keysize\n");
        return KM_ERROR_UNSUPPORTED_KEY_SIZE;
    }
    tlogd("km aes begin: key_size %u \n", key_node->key1_size);
    if (get_sym_purpose(key_node->purpose, &gp_purpose) != KM_ERROR_OK) {
        tloge("unsupported purpose\n");
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }
    if (get_aes_algorithm(key_node->block_mode, key_node->padding, &algorithm) != KM_ERROR_OK) {
        tloge("get aes gp algorithm failed\n");
        return KM_ERROR_UNSUPPORTED_BLOCK_MODE;
    }
    return km_aes_init(key_node, iv, key, gp_purpose, algorithm);
}

static keymaster_error_t do_km_aes_update(TEE_OperationHandle aes_handle,  uint8_t *in_data, uint32_t in_size,
                                          uint8_t *out_data, uint32_t *out_size)
{
    TEE_Result result;
    size_t tmp_out_size = (size_t)(*out_size);
    if (*out_size < in_size) {
        tloge("output buffer too small\n");
        return (keymaster_error_t)TEE_ERROR_BAD_PARAMETERS;
    }
    if (in_size == 0) {
        tloge("invalid update_size\n");
        return (keymaster_error_t)TEE_ERROR_BAD_PARAMETERS;
    }
    tlogd("update input:\n");
    result = TEE_CipherUpdate(aes_handle, in_data, (size_t)in_size, out_data, &tmp_out_size);
    if (result != TEE_SUCCESS) {
        tloge("TEE_CipherUpdate fail, ret is 0x%x\n", result);
        return KM_ERROR_UNKNOWN_ERROR;
    }

    tlogd("TEE_CipherUpdate test pass\n");
    tlogd("update output:\n");
    *out_size = tmp_out_size;
    return KM_ERROR_OK;
}

keymaster_error_t km_aes_update(key_auth *key_node, uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                uint32_t *out_size)
{
    keymaster_error_t ret;
    bool check_fail = ((key_node == NULL) || (out_size == NULL));
    if (check_fail) {
        tloge("key_node or out_size is null\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    TEE_OperationHandle aes_handle = (TEE_OperationHandle)key_node->crypto_ctxt;
    if (key_node->data_size > (UINT32_MAX - in_size)) {
        tloge("in_data size invalid:%u\n", in_size);
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }

    ret = do_km_aes_update(aes_handle, in_data, in_size, out_data, out_size);
    if (ret != KM_ERROR_OK) {
        tloge("do_km_aes_update failed\n");
        return ret;
    }
    tlogd("update data_size = %u\n", *out_size);
    return ret;
}

static keymaster_error_t pre_proc_km_aes_finish(uint32_t *out_size, uint32_t *tmp_out_size)
{
    if (out_size != NULL)
        *tmp_out_size = *out_size;

    bool condition = ((out_size != NULL) && (*out_size != 0));
    if (condition) {
        *out_size = 0;
    } else {
        tloge("the operation is failed\n");
        return KM_ERROR_INVALID_ARGUMENT;
    }

    return KM_ERROR_OK;
}

static keymaster_error_t proc_no_force_before_aes_finish(const key_auth *key_node, uint32_t tmp_out_size,
                                                         uint8_t **in_data, uint32_t *in_size)
{
    if (key_node->data_size != 0) {
        *in_data = key_node->data;
        *in_size = key_node->data_size;
    } else {
        tlogd("final input is 0\n");
        *in_data = NULL;
        *in_size = 0;
    }
    bool condition = ((key_node->data_size != 0) && (tmp_out_size < *in_size));
    if (condition) {
        tloge("output buffer too small:%u/%u\n", tmp_out_size, *in_size);
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t proc_pkcs7_pad_dec_after_aes_finish(const uint8_t *final_out_buffer, uint32_t final_out_size,
                                                             uint32_t tmp_out_size, uint8_t *out_data,
                                                             uint32_t *out_size)
{
    errno_t rc;
    if (tmp_out_size < final_out_size) {
        tloge("output buffer too small:%u/%u\n", tmp_out_size, final_out_size);
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }
    if (out_size != NULL)
        *out_size = final_out_size;
    bool condition = ((out_size != NULL) && (*out_size != 0));
    if (condition) {
        rc = memcpy_s(out_data, tmp_out_size, final_out_buffer, *out_size);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
    }

    return KM_ERROR_OK;
}

static keymaster_error_t proc_pkcs7_pad_enc_for_km_aes_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_size,
                                                              TEE_OperationHandle aes_handle,
                                                              uint32_t tmp_out_size, uint8_t *out_data,
                                                              uint32_t *out_size, int32_t force)
{
    TEE_Result result;
    size_t final_out_size = (size_t)tmp_out_size;
    if (force == 0) {
        in_data = key_node->data;
        in_size = key_node->data_size;
        if (tmp_out_size < in_size) {
            tloge("output buffer too small:%u/%u\n", tmp_out_size, in_size);
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
    }
    result = TEE_CipherDoFinal(aes_handle, in_data, in_size, out_data, &final_out_size);
    if (force == 0) {
        if (result != TEE_SUCCESS) {
            tloge("encrypt AES_Finish fail\n");
            return result;
        }
        tlogd("encrypt AES_Finish test pass\n");
        *out_size = final_out_size;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t proc_pkcs7_pad_dec_for_km_aes_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_size,
                                                              TEE_OperationHandle aes_handle,
                                                              uint32_t tmp_out_size, uint8_t *out_data,
                                                              uint32_t *out_size, int32_t force)
{
    TEE_Result result;
    keymaster_error_t ret = KM_ERROR_OK;
    size_t final_out_size = in_size;
    uint8_t *final_out_buffer = NULL;
    if (force == 0) {
        in_data = key_node->data;
        in_size = key_node->data_size;
        final_out_buffer = (uint8_t *)TEE_Malloc(in_size + PKCS7_PADDING_LEN, 0);
        if (final_out_buffer == NULL) {
            tloge("tempDate malloc failed, len=%u\n", in_size);
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        final_out_size = in_size + PKCS7_PADDING_LEN;
    }
    result = TEE_CipherDoFinal(aes_handle, in_data, in_size, final_out_buffer, &final_out_size);
    if (force == 0) {
        if (result != TEE_SUCCESS) {
            tloge("decrypt AES_Finish fail, %u\n", result);
            if (result != TEE_ERROR_BAD_FORMAT)
                ret = KM_ERROR_INVALID_INPUT_LENGTH;
            else
                ret = KM_ERROR_INVALID_ARGUMENT; /* cts require this err code while padding error */
            goto exit;
        }
        tlogd("decrypt AES_Finish test pass\n");
        ret = proc_pkcs7_pad_dec_after_aes_finish(final_out_buffer, final_out_size, tmp_out_size, out_data, out_size);
        if (ret != KM_ERROR_OK) {
            tloge("proc_pkcs7_pad_dec_after_aes_finish fail\n");
            goto exit;
        }
    }
exit:
    TEE_Free(final_out_buffer);
    final_out_buffer = NULL;
    return ret;
}

static keymaster_error_t proc_pkcs7_pad_km_aes_finish(key_auth *key_node, TEE_OperationHandle aes_handle,
                                                      uint32_t tmp_out_size, uint8_t *in_data, uint32_t in_size,
                                                      uint8_t *out_data, uint32_t *out_size, int32_t force)
{
    if (key_node->purpose == KM_PURPOSE_ENCRYPT)
        return proc_pkcs7_pad_enc_for_km_aes_finish(key_node, in_data, in_size, aes_handle,
                                                    tmp_out_size, out_data, out_size, force);
    else if (key_node->purpose == KM_PURPOSE_DECRYPT)
        return proc_pkcs7_pad_dec_for_km_aes_finish(key_node, in_data, in_size, aes_handle,
                                                    tmp_out_size, out_data, out_size, force);
    else
        return KM_ERROR_UNSUPPORTED_PURPOSE;
}

static keymaster_error_t proc_none_pad_km_aes_finish(key_auth *key_node, TEE_OperationHandle aes_handle,
                                                     uint32_t tmp_out_size, uint8_t *in_data, uint32_t in_size,
                                                     uint8_t *out_data, uint32_t *out_size, int32_t force)
{
    keymaster_error_t ret;
    uint8_t *data_buf     = in_data;
    uint32_t data_in_size = in_size;
    size_t final_out_size = (size_t)(tmp_out_size);
    TEE_Result result;

    if (force == 0) {
        ret = proc_no_force_before_aes_finish(key_node, tmp_out_size, &data_buf, &data_in_size);
        if (ret != KM_ERROR_OK) {
            tloge("proc no force before aes finish fail\n");
            return ret;
        }
    }
    result = TEE_CipherDoFinal(aes_handle, (void *)data_buf, (size_t)data_in_size, (void *)out_data, &final_out_size);
    if (force == 0) {
        if (result != TEE_SUCCESS) {
            tloge("TEE Cipher Do Final fail, %x\n", result);
            if (result == TEE_ERROR_BAD_FORMAT)
                return KM_ERROR_INVALID_ARGUMENT;
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
        if (out_size != NULL)
            *out_size = final_out_size;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t proc_all_pad_km_aes_finish(key_auth *key_node, uint32_t tmp_out_size, uint8_t *in_data,
    uint32_t in_size, uint8_t *out_data, uint32_t *out_size, int32_t force)
{
    TEE_OperationHandle aes_handle = (TEE_OperationHandle)key_node->crypto_ctxt;
    if (key_node->padding == KM_PAD_NONE)
        return proc_none_pad_km_aes_finish(key_node, aes_handle, tmp_out_size, in_data, in_size, out_data,
                                           out_size, force);
    else if (key_node->padding == KM_PAD_PKCS7)
        return proc_pkcs7_pad_km_aes_finish(key_node, aes_handle, tmp_out_size, in_data, in_size, out_data,
                                            out_size, force);
    else
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
}

keymaster_error_t km_aes_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                uint32_t *out_size, int32_t force)
{
    if (key_node == NULL) {
        tloge("key_node is null\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    uint32_t tmp_out_size = 0;
    keymaster_error_t ret;

    ret = pre_proc_km_aes_finish(out_size, &tmp_out_size);
    if (ret != KM_ERROR_OK) {
        tloge("pre_proc_km_aes_finish failed\n");
        return ret;
    }

    return proc_all_pad_km_aes_finish(key_node, tmp_out_size, in_data, in_size, out_data, out_size, force);
}

static keymaster_error_t proc_aes_gcm_enc_for_operation_update(key_auth *key_node, uint8_t *in_data, uint32_t in_size,
                                                               uint8_t *out_data, uint32_t *out_size,
                                                               uint32_t tmp_out_size)
{
    TEE_Result result;
    size_t update_out_size = (size_t)(tmp_out_size);
    if (key_node->crypto_ctxt == NULL) {
        tloge("context is NULL");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if (tmp_out_size < in_size) {
        tloge("output buffer too small, out_size=%u, in_size=%u\n", tmp_out_size, in_size);
        return (keymaster_error_t)TEE_ERROR_BAD_PARAMETERS;
    }
    tlogd("out_size %u, tmp_out_size %u, in_size %u\n", *out_size, tmp_out_size, in_size);
    result = TEE_AEUpdate((TEE_OperationHandle)(key_node->crypto_ctxt), in_data, in_size, out_data, &update_out_size);
    if (result != TEE_SUCCESS) {
        tloge("TEE_AEUpdate failed\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if (update_out_size > tmp_out_size) {
        tloge("produced out buffer %zu, is too long than real buffer %u\n", update_out_size, tmp_out_size);
    } else {
        *out_size = (uint32_t)update_out_size;
    }
    tlogd("gcm aes_ae_update success\n");
    return KM_ERROR_OK;
}

static keymaster_error_t proc_aes_gcm_dec_for_operation_update(key_auth *key_node, uint8_t *in_data, uint32_t in_size,
                                                               uint8_t *out_data, uint32_t *out_size,
                                                               uint32_t tmp_out_size)
{
    keymaster_error_t ret;
    int32_t rc;
    uint32_t tag_len_in_bytes = (key_node->tag_len_bit / BITS_ONE_BYTE);
    if (key_node->crypto_ctxt == NULL) {
        tloge("context is NULL");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    ret = asymmetric_update(key_node, in_data, in_size);
    /* append in_data to key_node data */
    if (ret != KM_ERROR_OK) {
        tloge("aes gcm decrypt update in data error:%d\n", ret);
        return ret;
    }
    /* key_node data bigger than tag, need do decryption */
    if (key_node->data_size > tag_len_in_bytes) {
        /* check input and output params */
        if (tmp_out_size < key_node->data_size - tag_len_in_bytes) {
            tloge("invalid params, out_size=%u, key_node->data_size=%u, tag_len_in_bytes=%u\n",
                  tmp_out_size, key_node->data_size, tag_len_in_bytes);
            return (keymaster_error_t)TEE_ERROR_BAD_PARAMETERS;
        }
        /* must reserve tag for finish */
        uint32_t body_len = (key_node->data_size - tag_len_in_bytes);
        size_t update_out_size = tmp_out_size;

        TEE_Result result = TEE_AEUpdate((TEE_OperationHandle)(key_node->crypto_ctxt), key_node->data, body_len,
            out_data, (size_t *)&update_out_size);
        if (result != TEE_SUCCESS) {
            tloge("TEE_AEUpdate failed\n");
            return KM_ERROR_UNKNOWN_ERROR;
        }
        /* reserve the last tag size input */
        rc = memmove_s(key_node->data, key_node->data_size, key_node->data + (key_node->data_size - tag_len_in_bytes),
                       tag_len_in_bytes);
        if (rc != 0) {
            tloge("memmove_s failed, rc 0x%x\n", rc);
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        key_node->data_size = tag_len_in_bytes;
        if (update_out_size > tmp_out_size) {
            tloge("produced out buffer %zu, is too long than real buffer %u\n", update_out_size, tmp_out_size);
        } else {
            *out_size = (size_t)update_out_size;
        }
    }
    tlogd("gcm aes_ae_update success\n");
    return KM_ERROR_OK;
}

static keymaster_error_t proc_aes_gcm_enc_dec_for_operation_update(key_auth *key_node, uint8_t *in_data,
                                                                   uint32_t in_size, uint8_t *out_data,
                                                                   uint32_t *out_size, uint32_t tmp_out_size)
{
    tlogd("aes gcm update in_size=%u\n", in_size);
    key_node->data_started_gcm = true;
    /* just use asymmetric func to store input data */
    if (key_node->purpose == KM_PURPOSE_DECRYPT)
        return proc_aes_gcm_dec_for_operation_update(key_node, in_data, in_size, out_data, out_size, tmp_out_size);
    else if (key_node->purpose == KM_PURPOSE_ENCRYPT)
        return proc_aes_gcm_enc_for_operation_update(key_node, in_data, in_size, out_data, out_size, tmp_out_size);
    else
        return KM_ERROR_UNSUPPORTED_PURPOSE;
}

static keymaster_error_t proc_aad_data_for_aes_gcm(key_auth *key_node, keymaster_blob_t *aad_data)
{
    /* calculate additional data */
    if (key_node->crypto_ctxt == NULL) {
        tloge("context is NULL");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (aad_data->data_length > 0)
        TEE_AEUpdateAAD((TEE_OperationHandle)(key_node->crypto_ctxt), aad_data->data_addr, aad_data->data_length);
    tlogd("proc_aad_data_for_aes_gcm finish\n");
    return KM_ERROR_OK;
}
keymaster_error_t proc_aes_gcm_for_operation_update(key_auth *key_node,
    const keymaster_key_param_set_t *params_enforced, uint8_t *in_data, uint32_t in_size,
    uint8_t *out_data, uint32_t *out_size)
{
    keymaster_error_t ret = KM_ERROR_OK;
    keymaster_blob_t aad_data = { NULL, 0 };
    uint32_t tmp_out_size = *out_size;
    *out_size = 0;
    /* additional data may be provided in multiple calls to update(), but only until input data has been provided */
    if (get_key_param(KM_TAG_ASSOCIATED_DATA, &aad_data, params_enforced) == 0) {
        if ((aad_data.data_length != 0) && (key_node->data_started_gcm == true)) {
            tloge("additional data must be put before input data\n");
            return KM_ERROR_INVALID_TAG;
        }

        ret = proc_aad_data_for_aes_gcm(key_node, &aad_data);
        if (ret != KM_ERROR_OK) {
            tloge("proc_aes_gcm_for_operation_update failed\n");
            return ret;
        }
    }
    /* reserve input data for finish */
    if ((in_data != NULL) && (in_size != 0))
        return proc_aes_gcm_enc_dec_for_operation_update(key_node, in_data, in_size, out_data, out_size, tmp_out_size);
    return ret;
}


static keymaster_error_t prepare_aes_gcm_enc_outbuff(uint8_t **tmp_out, uint32_t tmp_out_len, uint8_t **tag_out,
    uint32_t tag_out_len)
{
    if (tmp_out == NULL || tag_out == NULL) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    *tmp_out = (uint8_t *)TEE_Malloc(tmp_out_len, TEE_MALLOC_FILL_ZERO);
    if (*tmp_out == NULL) {
        tloge("alloc tmp_out failed\n");
        return (keymaster_error_t)TEE_ERROR_OUT_OF_MEMORY;
    }
    *tag_out = TEE_Malloc(tag_out_len, TEE_MALLOC_FILL_ZERO);
    if (*tag_out == NULL) {
        tloge("alloc tag out failed\n");
        return  (keymaster_error_t)TEE_ERROR_OUT_OF_MEMORY;
    }
    return KM_ERROR_OK;
}


static keymaster_error_t aes_gcm_enc_finish(key_auth *key_node, uint8_t *out_data, uint32_t *out_size, uint32_t tag_len)
{
    keymaster_error_t ret;
    uint8_t *tmp_out = NULL;
    size_t tag_out_len = tag_len;
    uint8_t *tag_out = NULL;

    if ((UINT32_MAX - key_node->data_size) < AES_BLOCK_SIZE_IN_BYTES) {
        tloge("in_size %u, AES_BLOCK_SIZE_IN_BYTES %u invalid\n", key_node->data_size, AES_BLOCK_SIZE_IN_BYTES);
        ret = (keymaster_error_t)TEE_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    size_t temp_out_len = key_node->data_size + AES_BLOCK_SIZE_IN_BYTES;
    ret = prepare_aes_gcm_enc_outbuff(&tmp_out, (uint32_t)temp_out_len, &tag_out, (uint32_t)tag_out_len);
    if (ret != KM_ERROR_OK)
        goto end;

    if (TEE_AEEncryptFinal((TEE_OperationHandle)(key_node->crypto_ctxt), key_node->data, key_node->data_size,
        tmp_out, &temp_out_len, tag_out, &tag_out_len) != TEE_SUCCESS) {
        tloge("do encrypt finish failed!\n");
        ret = KM_ERROR_UNKNOWN_ERROR;
        goto end;
    }

    if (memcpy_s(out_data, *out_size, tmp_out, temp_out_len) != EOK ||
        memcpy_s(out_data + temp_out_len, *out_size - temp_out_len, tag_out, tag_out_len) != EOK) {
        tloge("fill final out buffer  failed\n");
        ret = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        goto end;
    }
    *out_size = temp_out_len + tag_out_len;
    tlogd("encrypt:aes ae final success\n");
end:
    TEE_FreeOperation((TEE_OperationHandle)key_node->crypto_ctxt);
    key_node->crypto_ctxt = NULL;
    if (tmp_out != NULL) {
        TEE_Free(tmp_out);
        tmp_out = NULL;
    }
    if (tag_out != NULL) {
        TEE_Free(tag_out);
        tag_out = NULL;
    }
    return ret;
}

static keymaster_error_t aes_gcm_dec_finish(key_auth *key_node, uint8_t *out_data, uint32_t *out_size, uint32_t tag_len)
{
    keymaster_error_t ret = KM_ERROR_OK;
    uint8_t *tmp_out = NULL;
    size_t temp_out_len = 0;

    if (key_node->data_size >= tag_len) {
        temp_out_len = key_node->data_size - tag_len + AES_BLOCK_SIZE_IN_BYTES;
    } else {
        tloge("final input data size %u, is shorter than tag len %u\n", key_node->data_size, tag_len);
        ret = KM_ERROR_INVALID_INPUT_LENGTH;
        goto end;
    }
    tmp_out = TEE_Malloc(temp_out_len, TEE_MALLOC_FILL_ZERO);
    if (tmp_out == NULL) {
        tloge("alloc tmp_out failed\n");
        ret = (keymaster_error_t)TEE_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    TEE_Result result = TEE_AEDecryptFinal((TEE_OperationHandle)(key_node->crypto_ctxt), key_node->data,
        key_node->data_size - tag_len, tmp_out, &temp_out_len, key_node->data + key_node->data_size - tag_len, tag_len);
    if (result != TEE_SUCCESS) {
        tloge("TEE AE decrypt final failed!\n");
        if (result == TEE_ERROR_BAD_PARAMETERS)
            ret = KM_ERROR_VERIFICATION_FAILED;
        else
            ret = KM_ERROR_UNKNOWN_ERROR;
        goto end;
    }
    if ((tmp_out != NULL) && memcpy_s(out_data, *out_size, tmp_out, temp_out_len) != EOK) {
        tloge("memcpy_s failed\n");
        ret = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    *out_size = temp_out_len;
    tlogd("decrypt:aes_ae_final success\n");
end:
    TEE_FreeOperation((TEE_OperationHandle)key_node->crypto_ctxt);
    key_node->crypto_ctxt = NULL;
    if (tmp_out != NULL)
        TEE_Free(tmp_out);
    return ret;
}

static keymaster_error_t proc_aes_gcm_with_no_force_enc_dec(key_auth *key_node, uint8_t *out_data, uint32_t *out_size)
{
    bool check_fail = (key_node == NULL || key_node->crypto_ctxt == NULL);
    if (check_fail) {
        tloge("NULL pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    uint32_t tag_len = (key_node->tag_len_bit / BITS_ONE_BYTE);

    if (key_node->purpose == KM_PURPOSE_ENCRYPT)
        return aes_gcm_enc_finish(key_node, out_data, out_size, tag_len);
    else if (key_node->purpose == KM_PURPOSE_DECRYPT)
        return aes_gcm_dec_finish(key_node, out_data, out_size, tag_len);
    else
        return KM_ERROR_UNSUPPORTED_PURPOSE;
}

keymaster_error_t proc_aes_gcm_with_no_force_for_operation_finish(key_auth *key_node,
    const keymaster_key_param_set_t *params_enforced, uint8_t *out_data, uint32_t *out_size)
{
    keymaster_error_t ret;
    /* add gcm by soft crypt engine */
    keymaster_blob_t aad_data = { NULL, 0 };

    /* additional data may be provided in multiple calls to update(), but only until input data has been provided */
    if (get_key_param(KM_TAG_ASSOCIATED_DATA, &aad_data, params_enforced) == 0) {
        bool check_fail = ((aad_data.data_length != 0) && (key_node->data_started_gcm == true));
        if (check_fail) {
            tloge("additional data must be put before input data\n");
            return KM_ERROR_INVALID_TAG;
        }
    }
    ret = proc_aad_data_for_aes_gcm(key_node, &aad_data);
    if (ret != KM_ERROR_OK) {
        tloge("proc_aes_gcm_for_operation_update failed\n");
        return ret;
    }
    tlogd("key_node->aad_data_size is %u\n", key_node->aad_data_size);
    tlogd("key_node->data_size is %u\n", key_node->data_size);
    return proc_aes_gcm_with_no_force_enc_dec(key_node, out_data, out_size);
}

