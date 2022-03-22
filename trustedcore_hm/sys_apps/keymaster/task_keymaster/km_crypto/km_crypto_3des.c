/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster 3des cipher functions implementation
 * Create: 2020-12-01
 */

#include "securec.h"
#include "keymaster_defs.h"
#include "tee_crypto_api.h"
#include "km_common.h"
#include "km_keynode.h"
#include "km_crypto.h"
#include "km_crypto_adaptor.h"
#define TRIPLE_DES_MAX_KEY_SIZE 192

keymaster_error_t triple_des_init(const keymaster_blob_t *iv, keymaster_blob_t *key, key_auth *key_node)
{
    TEE_Result result;
    uint32_t algorithm = TEE_ALG_DES3_CBC_NOPAD;
    uint32_t gp_purpose = TEE_MODE_ENCRYPT;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle key_object = TEE_HANDLE_NULL;
    bool condition_check = (key_node == NULL || iv == NULL || key == NULL);
    if (condition_check) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }

    if (get_sym_purpose(key_node->purpose, &gp_purpose) != KM_ERROR_OK) {
        tloge("purpose is error\n");
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }

    if (check_block_mode(key_node->block_mode, &algorithm) != KM_ERROR_OK) {
        tloge("invalied block_mode\n");
        return KM_ERROR_UNSUPPORTED_BLOCK_MODE;
    }
    keymaster_error_t ret = KM_ERROR_OK;
    result = init_key_obj(KM_ALGORITHM_TRIPLE_DES, KM_DIGEST_NONE, key_node->key1_size, &key_object, key);
    if (result != TEE_SUCCESS) {
        tloge("init key object failed, ret 0x%x\n", result);
        ret = KM_ERROR_UNKNOWN_ERROR;
        goto release;
    }
    result = init_key_operation(&op_handle, algorithm, gp_purpose, key_node->key1_size, &key_object);
    if (result != TEE_SUCCESS) {
        tloge("alloc crypto operation failed, result=0x%x\n", result);
        ret = KM_ERROR_UNKNOWN_ERROR;
        goto op_error;
    }
    key_node->crypto_ctxt = (void *)op_handle;
    TEE_CipherInit((TEE_OperationHandle)key_node->crypto_ctxt, iv->data_addr, iv->data_length);
    goto release;
op_error:
    TEE_FreeOperation(op_handle);
    op_handle = TEE_HANDLE_NULL;
release:
    (void)memset_s(key->data_addr, key->data_length, 0, key->data_length);
    TEE_FreeTransientObject(key_object);
    key_object = TEE_HANDLE_NULL;
    return ret;
}

static void free_crypto_ctxt(key_auth *key_node)
{
    TEE_FreeOperation((TEE_OperationHandle)key_node->crypto_ctxt);
    key_node->crypto_ctxt = NULL;
}

keymaster_error_t triple_des_update(key_auth *key_node, uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                    uint32_t *out_size)
{
    bool check_fail = ((key_node == NULL) || (in_data == NULL) || (out_data == NULL) || (out_size == NULL));
    if (check_fail)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    TEE_OperationHandle des_handle = (TEE_OperationHandle)key_node->crypto_ctxt;
    TEE_Result result;
    size_t tmp_out_size = (size_t)(*out_size);
    result = TEE_CipherUpdate(des_handle, in_data, in_size, out_data, &tmp_out_size);
    if (result != TEE_SUCCESS) {
        tloge("TEE_CipherUpdate faile. ret=0x%x\n", result);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    *out_size = tmp_out_size;
    return KM_ERROR_OK;
}

static keymaster_error_t check_out_size(uint32_t *out_size, uint32_t *out_val)
{
    keymaster_error_t ret = KM_ERROR_OK;

    if (out_size != NULL)
        *out_val = *out_size;

    bool condition_check = ((out_size != NULL) && *out_size);
    if (condition_check)
        *out_size = 0;
    else
        ret = KM_ERROR_INVALID_ARGUMENT;
    return ret;
}

static keymaster_error_t check_tee_result(TEE_Result result, uint32_t *out_size, uint32_t in_size)
{
    keymaster_error_t ret;
    if (result == TEE_SUCCESS) {
        ret = KM_ERROR_OK;
        tlogd("TEE_DES_Block test pass\n");
        if (out_size != NULL)
            *out_size = in_size;
    } else {
        tloge("TEE_DES_Block fail\n");
        ret = KM_ERROR_UNKNOWN_ERROR;
    }
    return ret;
}

static keymaster_error_t nopadding_func(key_auth *key_node, uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                        uint32_t *out_size, int force)
{
    if (key_node == NULL)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    TEE_OperationHandle des_handle = (TEE_OperationHandle)key_node->crypto_ctxt;
    TEE_Result result;
    uint32_t tmp_out_size = 0;
    keymaster_error_t ret;

    ret = check_out_size(out_size, &tmp_out_size);
    if (ret != KM_ERROR_OK)
        goto error;

    if (force == 0) {
        if (key_node->data_size) {
            in_data = key_node->data;
            in_size = key_node->data_size;
        } else {
            tlogd("final input is 0\n");
            in_data = NULL;
            in_size = 0;
        }
        if (key_node->data_size && tmp_out_size < in_size) {
            tloge("output buffer too small:%u/%u\n", tmp_out_size, in_size);
            ret = KM_ERROR_INVALID_INPUT_LENGTH;
            goto error;
        }
    }
    result = TEE_CipherDoFinal(des_handle, in_data, in_size, out_data, (size_t *)&tmp_out_size);
    if (force == 0) {
        ret = check_tee_result(result, out_size, tmp_out_size);
        if (ret != KM_ERROR_OK)
            goto error;
    }
error:
    free_crypto_ctxt(key_node);
    return ret;
}

static keymaster_error_t pkcs7_encrypt_fill_data(const key_auth *key_node, uint8_t *in_data, uint32_t in_size)
{
    errno_t rc;
    rc = memset_s(in_data, in_size, PKCS7_PADDING_LEN_DES - (key_node->data_size % PKCS7_PADDING_LEN_DES), in_size);
    if (rc != EOK) {
        tloge("memset_s failed, rc 0x%x\n", rc);
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    if (key_node->data_size != 0) {
        rc = memcpy_s(in_data, in_size, key_node->data, key_node->data_size);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
    }
    return KM_ERROR_OK;
}

static keymaster_error_t pkcs7_encrypt_func(key_auth *key_node, uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                            uint32_t *out_size, int force)
{
    if (key_node == NULL)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    TEE_OperationHandle des_handle = (TEE_OperationHandle)key_node->crypto_ctxt;
    TEE_Result result;
    keymaster_error_t ret;
    uint32_t tmp_out_size = 0;

    ret = check_out_size(out_size, &tmp_out_size);
    if (ret != KM_ERROR_OK)
        goto error;

    if (force == 0) {
        /* pkcs7 padding maybe key_node->data_size == 0 */
        in_size = (key_node->data_size / PKCS7_PADDING_LEN_DES + 1) * PKCS7_PADDING_LEN_DES;
        if (tmp_out_size < in_size) {
            tloge("output buffer too small:%u/%u\n", tmp_out_size, in_size);
            ret = KM_ERROR_INVALID_INPUT_LENGTH;
            goto error;
        }

        in_data = (uint8_t *)TEE_Malloc(in_size, 0);
        if (in_data == NULL) {
            tloge("tempDate malloc failed, len=%u\n", in_size);
            ret = KM_ERROR_MEMORY_ALLOCATION_FAILED;
            goto error;
        }
        ret = pkcs7_encrypt_fill_data(key_node, in_data, in_size);
        if (ret != KM_ERROR_OK) {
            tloge("encrypt fill data failed, ret=%d\n", ret);
            TEE_Free(in_data);
            in_data = NULL;
            goto error;
        }
    }
    result = TEE_CipherDoFinal(des_handle, in_data, in_size, out_data, (size_t *)&tmp_out_size);
    if (force == 0) {
        TEE_Free(in_data);
        in_data = NULL;
        ret     = check_tee_result(result, out_size, tmp_out_size);
        if (ret != KM_ERROR_OK)
            tloge("error check flag\n");
    }
error:
    free_crypto_ctxt(key_node);
    return ret;
}

static int check_pkcs7_output(uint8_t n, uint32_t b, const uint8_t *data)
{
    uint32_t i;
    if (data == NULL) {
        tloge("the data is null\n");
        return -1;
    }
    bool condition_check = ((n == 0) || (n > PKCS7_PADDING_LEN_DES) || (b < (uint32_t)n));
    if (condition_check == true) {
        tloge("invalied pkcs7 padding, n=%d\n", n);
        return -1;
    }

    for (i = 1; i < n; i++) {
        if (data[b - 1 - i] != n) {
            tloge("invalid pkcs7 padding, %u!=%u\n", data[b - 1 - i], n);
            return -1;
        }
    }
    return 0;
}

static keymaster_error_t pkcs7_decrypt_fill_data(uint8_t **temp_data, uint32_t in_size, uint32_t tmp_out_size,
                                                 const key_auth *key_node, uint32_t *out_size, uint8_t *out_data)
{
    uint32_t b = in_size;
    uint8_t n  = (*temp_data)[b - 1];
    errno_t rc;
    int ret = check_pkcs7_output(n, b, *temp_data);
    if (ret) {
        tloge("check_pkcs7_output failed\n");
        TEE_Free(*temp_data);
        *temp_data = NULL;
        return KM_ERROR_INVALID_ARGUMENT;
    }

    if (tmp_out_size < (key_node->data_size - n)) {
        tloge("output buffer too small:%u, %u\n", tmp_out_size, (key_node->data_size - n));
        TEE_Free(*temp_data);
        *temp_data = NULL;
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }
    if (out_size != NULL)
        *out_size = key_node->data_size - n;

    bool condition_check = (out_size && *out_size);
    if (condition_check) {
        rc = memcpy_s(out_data, *out_size, *temp_data, *out_size);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            TEE_Free(*temp_data);
            *temp_data = NULL;
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
    }
    return KM_ERROR_OK;
}

static keymaster_error_t pkcs7_decrypt_func(key_auth *key_node, uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                            uint32_t *out_size, int force)
{
    TEE_OperationHandle des_handle = (TEE_OperationHandle)key_node->crypto_ctxt;
    keymaster_error_t ret          = KM_ERROR_OK;
    size_t tmp_out_size            = 0;
    uint8_t *temp_data              = NULL;
    if (out_size && *out_size) {
        tmp_out_size = (size_t)*out_size;
        *out_size    = 0;
    } else {
        ret = KM_ERROR_INVALID_ARGUMENT;
        goto END;
    }

    if (force != 0) {
        if (TEE_CipherDoFinal(des_handle, in_data, in_size, temp_data, &tmp_out_size) != TEE_SUCCESS) {
            tloge("decrypt TEE CipherDoFinal fail\n");
            ret = KM_ERROR_INVALID_INPUT_LENGTH;
        }
        goto END;
    }
    /* pkcs7 lastblock never be NULL */
    in_data = key_node->data;
    in_size = key_node->data_size;
    if (in_size == 0) {
        tloge("Invalid pkcs7 input length\n");
        ret = KM_ERROR_INVALID_INPUT_LENGTH;
        goto END;
    }
    temp_data = (uint8_t *)TEE_Malloc(in_size, 0);
    if (temp_data == NULL) {
        tloge("malloc in size fail\n");
        ret = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        goto END;
    }
    tmp_out_size = in_size;
    if (TEE_CipherDoFinal(des_handle, in_data, in_size, temp_data, &tmp_out_size) != TEE_SUCCESS) {
        tloge("decrypt TEE_CipherDoFinal fail\n");
        TEE_Free(temp_data);
        temp_data = NULL;
        ret      = KM_ERROR_INVALID_INPUT_LENGTH;
        goto END;
    }
    tlogd("decrypt TEE_CipherDoFinal test pass\n");
    ret = pkcs7_decrypt_fill_data(&temp_data, in_size, tmp_out_size, key_node, out_size, out_data);
    TEE_Free(temp_data);
    temp_data = NULL;
END:
    free_crypto_ctxt(key_node);
    return ret;
}

static keymaster_error_t handle_pad_pkcs7(key_auth *key_node, uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                          uint32_t *out_size, int force)
{
    keymaster_purpose_t purpose = key_node->purpose;
    if (purpose == KM_PURPOSE_ENCRYPT) {
        return pkcs7_encrypt_func(key_node, in_data, in_size, out_data, out_size, force);
    } else if (purpose == KM_PURPOSE_DECRYPT) {
        return pkcs7_decrypt_func(key_node, in_data, in_size, out_data, out_size, force);
    } else {
        tloge("invalid purpose, %d\n", purpose);
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }
}

keymaster_error_t triple_des_finish(key_auth *key_node, uint8_t *in_data, uint32_t in_size, uint8_t *out_data,
                                    uint32_t *out_size, int force)
{
    if (key_node == NULL) {
        tloge("key_node is null\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    keymaster_padding_t padding = key_node->padding;
    if (padding == KM_PAD_NONE) {
        return nopadding_func(key_node, in_data, in_size, out_data, out_size, force);
    } else if (padding == KM_PAD_PKCS7) {
        return handle_pad_pkcs7(key_node, in_data, in_size, out_data, out_size, force);
    } else {
        tloge("invalid padding, %d\n", padding);
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }
    return KM_ERROR_OK;
}

keymaster_error_t km_3des_begin(key_auth *key_node, keymaster_blob_t *key,
    const keymaster_blob_t *iv)
{
    keymaster_error_t ret;
    /* for save block un-align data */
    if (key_node->data == NULL) {
        ret = alloc_data_buff_for_operation_symmetric_begin(key_node, DES3_BLOCKS);
        if (ret != KM_ERROR_OK) {
            tloge("alloc_data_buff_for_operation_symmetric_begin failed");
            return ret;
        }
    }
    tlogw("Warning: An insecure crypto service is being used: 3DES\n");
    return triple_des_init(iv, key, key_node);
}