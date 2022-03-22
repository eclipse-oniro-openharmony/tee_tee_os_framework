/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Safety operator
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#include "invoke.h"
#include "tee_log.h"
#include "securec.h"
#include "crypto_operation.h"
#include "kms_tag_api.h"
#include "kms_pub_def.h"
#include "kms_params_check.h"
#include "kms_key_storage.h"

#ifdef DEF_ENG
#define PRINT_MAX_LEN (1024 * 5)
#define PRINT_ONE_LEN 2048
#define PRINT_ONE_LINE 16
#define FIX_ONE_PRINT 3
void mem_print(const char *head, const uint8_t *buf, uint32_t len)
{
    char p[PRINT_ONE_LEN] = {0};
    uint32_t i = 0;
    uint32_t j = 0;
    if (buf == NULL) {
        tloge("buffer is null\n");
        return;
    }
    if (len > PRINT_MAX_LEN) {
        tloge("len too large %u for print\n", len);
        len = PRINT_MAX_LEN;
    }
    tloge("%s,buffer len %u content:\n", head, len);
    while (i < len) {
        uint8_t c = buf[i];
        if (snprintf_s(p + j, PRINT_ONE_LEN - j, FIX_ONE_PRINT, " %02x", c) == -1) {
            tloge("memory dump fail %u\n", j);
            return;
        }
        j += FIX_ONE_PRINT;
        if ((i + 1) % PRINT_ONE_LINE == 0) {
            tloge("%s\n", p);
            j = 0;
            (void)memset_s(p, PRINT_ONE_LEN, 0, PRINT_ONE_LEN);
        }
        i++;
    }
    tloge("%s\n", p);
}
#else
void mem_print(const char *head, const uint8_t *buf, uint32_t len)
{
    (void)head;
    (void)buf;
    (void)len;
}
#endif

static void free_key_blob(struct kms_buffer_data *key_blob)
{
    bool free_keyblob = ((key_blob != NULL) && (key_blob->buffer != NULL) && (key_blob->length != 0));
    if (free_keyblob) {
        /* sensitive information clear */
        (void)memset_s(key_blob->buffer, key_blob->length, 0, key_blob->length);
        TEE_Free(key_blob->buffer);
        key_blob->buffer = NULL;
        key_blob->length = 0;
    }
}

static void free_param_set(struct kms_buffer_data *param_set)
{
    bool condition = ((param_set != NULL) && (param_set->buffer != NULL));
    if (condition) {
        TEE_Free(param_set->buffer);
        param_set->buffer = NULL;
        param_set->length = 0;
    }
}
/*
 * in :operation.params[INDEX_0] key_id
 * in :operation.params[INDEX_1] key tags
 */
int32_t kms_cmd_create_key(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data key_blob = { 0, NULL };
    struct kms_buffer_data param_set = { 0, NULL };

    TEE_Result ret = tag_input_to_param_set(params[INDEX_1], &param_set);
    if (ret != TEE_SUCCESS) {
        tloge("cmd create key: tag param to datas fail\n");
        goto mem_free;
    }

    ret = kms_create_params_check(&param_set);
    if (ret != TEE_SUCCESS) {
        tloge("cmd create key: tag param check does not pass\n");
        goto mem_free;
    }

    key_blob.length = KEY_BLOB_MAX_SIZE;
    key_blob.buffer = (uint8_t *)TEE_Malloc(key_blob.length, TEE_MALLOC_FILL_ZERO);
    if (key_blob.buffer == NULL) {
        tloge("kms cmd create key: malloc keyblob fail\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto mem_free;
    }
    ret = kms_create_key(&param_set, &key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("kms cmd create key: create key fail\n");
        goto mem_free;
    }
    struct kms_buffer_data in_key;
    in_key.buffer = params[INDEX_0].memref.buffer;
    in_key.length = params[INDEX_0].memref.size;
    ret = kms_store_key(&in_key, &key_blob, &param_set);
    if (ret != TEE_SUCCESS)
        tloge("kms cmd create key: save key fail\n");

mem_free:
    free_key_blob(&key_blob);
    free_param_set(&param_set);
    return (int32_t)ret;
}

/*
 * in :operation.params[INDEX_0] key blob or key id
 * in :operation.params[INDEX_1] use key tags
 * in :operation.params[INDEX_2] src data
 * out:operation.params[INDEX_3] encrypto data
 */
int32_t kms_cmd_encrypto(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data key_blob = { 0, NULL };
    struct kms_buffer_data param_set = { 0, NULL };

    struct kms_buffer_data in_key;
    in_key.buffer = params[INDEX_0].memref.buffer;
    in_key.length = params[INDEX_0].memref.size;
    TEE_Result ret = kms_get_key(&in_key, &key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("cmd encrypto key: get key fail\n");
        goto mem_free;
    }
    ret = tag_input_to_param_set(params[INDEX_1], &param_set);
    if (ret != TEE_SUCCESS) {
        tloge("cmd encrypto key: tag param to datas fail\n");
        goto mem_free;
    }
    struct kms_buffer_data in_data = { 0 };
    in_data.buffer = params[INDEX_2].memref.buffer;
    in_data.length = params[INDEX_2].memref.size;
    struct kms_buffer_data out_data = { 0 };
    out_data.buffer = params[INDEX_3].memref.buffer;
    out_data.length = params[INDEX_3].memref.size;
    ret = kms_crypto(&key_blob, &param_set, KMS_MODE_ENCRYPT, &in_data, &out_data);
    if (ret != TEE_SUCCESS) {
        tloge("cmd encrypto key: encrypto fail\n");
        goto mem_free;
    }
    params[INDEX_3].memref.size = out_data.length;

mem_free:
    kms_release_key(&in_key, &key_blob);
    free_param_set(&param_set);
    return (int32_t)ret;
}

/*
 * in :operation.params[INDEX_0] key blob or key id
 * in :operation.params[INDEX_1] use key tags
 * in :operation.params[INDEX_2] encrypto data
 * out:operation.params[INDEX_3] src data
 */
int32_t kms_cmd_decrypto(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data key_blob = { 0, NULL };
    struct kms_buffer_data param_set = { 0, NULL };

    struct kms_buffer_data in_key;
    in_key.buffer = params[INDEX_0].memref.buffer;
    in_key.length = params[INDEX_0].memref.size;
    TEE_Result ret = kms_get_key(&in_key, &key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("cmd decrypto key: get key fail\n");
        goto mem_free;
    }
    ret = tag_input_to_param_set(params[INDEX_1], &param_set);
    if (ret != TEE_SUCCESS) {
        tloge("cmd decrypto: tag param to datas fail\n");
        goto mem_free;
    }
    struct kms_buffer_data in_data = { 0 };
    in_data.buffer = params[INDEX_2].memref.buffer;
    in_data.length = params[INDEX_2].memref.size;
    struct kms_buffer_data out_data = { 0 };
    out_data.buffer = params[INDEX_3].memref.buffer;
    out_data.length = params[INDEX_3].memref.size;
    ret = kms_crypto(&key_blob, &param_set, KMS_MODE_DECRYPT, &in_data, &out_data);
    if (ret != TEE_SUCCESS) {
        tloge("cmd decrypto key: decrypto fail\n");
        goto mem_free;
    }
    params[INDEX_3].memref.size = out_data.length;

mem_free:
    kms_release_key(&in_key, &key_blob);
    free_param_set(&param_set);
    return (int32_t)ret;
}

/*
 * in :operation.params[INDEX_0] use key tags
 * in :operation.params[INDEX_1] src data
 * out:operation.params[INDEX_2] hash data
 */
int32_t kms_cmd_digest(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data param_set = { 0, NULL };
    TEE_Result ret = tag_input_to_param_set(params[INDEX_0], &param_set);
    if (ret != TEE_SUCCESS) {
        tloge("cmd digest: tag param to datas fail\n");
        goto mem_free;
    }

    struct kms_buffer_data in_data = { 0 };
    in_data.buffer = params[INDEX_1].memref.buffer;
    in_data.length = params[INDEX_1].memref.size;
    struct kms_buffer_data out_data = { 0 };
    out_data.buffer = params[INDEX_2].memref.buffer;
    out_data.length = params[INDEX_2].memref.size;
    ret = kms_digest(&param_set, &in_data, &out_data);
    if (ret != TEE_SUCCESS) {
        tloge("cmd digest: digest fail\n");
        goto mem_free;
    }
    params[INDEX_2].memref.size = out_data.length;

mem_free:
    free_param_set(&param_set);
    return ret;
}

/*
 * in :operation.params[INDEX_0] key blob or key id
 * in :operation.params[INDEX_1] use key tags
 * in :operation.params[INDEX_2] src data
 * out:operation.params[INDEX_3] sign res data
 */
int32_t kms_cmd_sign(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data key_blob = { 0, NULL };
    struct kms_buffer_data param_set = { 0, NULL };

    struct kms_buffer_data in_key;
    in_key.buffer = params[INDEX_0].memref.buffer;
    in_key.length = params[INDEX_0].memref.size;
    TEE_Result ret = kms_get_key(&in_key, &key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("cmd sign: get key fail\n");
        goto mem_free;
    }
    ret = tag_input_to_param_set(params[INDEX_1], &param_set);
    if (ret != TEE_SUCCESS) {
        tloge("cmd sign: tag param to datas fail\n");
        goto mem_free;
    }
    struct kms_buffer_data in_data = { 0 };
    in_data.buffer = params[INDEX_2].memref.buffer;
    in_data.length = params[INDEX_2].memref.size;
    struct kms_buffer_data out_data = { 0 };
    out_data.buffer = params[INDEX_3].memref.buffer;
    out_data.length = params[INDEX_3].memref.size;
    ret = kms_sign_verify(&key_blob, &param_set, KMS_MODE_SIGN, &in_data, &out_data);
    if (ret != TEE_SUCCESS) {
        tloge("cmd sign key: sign fail\n");
        goto mem_free;
    }
    params[INDEX_3].memref.size = out_data.length;

mem_free:
    kms_release_key(&in_key, &key_blob);
    free_param_set(&param_set);
    return (int32_t)ret;
}

/*
 * in :operation.params[INDEX_0] key blob or key id
 * in :operation.params[INDEX_1] use key tags
 * in :operation.params[INDEX_2] src data
 * in :operation.params[INDEX_3] sign res data
 */
int32_t kms_cmd_verify(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data key_blob = { 0, NULL };
    struct kms_buffer_data param_set = { 0, NULL };

    struct kms_buffer_data in_key;
    in_key.buffer = params[INDEX_0].memref.buffer;
    in_key.length = params[INDEX_0].memref.size;
    TEE_Result ret = kms_get_key(&in_key, &key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("cmd verify: get key fail\n");
        goto mem_free;
    }
    ret = tag_input_to_param_set(params[INDEX_1], &param_set);
    if (ret != TEE_SUCCESS) {
        tloge("cmd verify: tag param to datas fail\n");
        goto mem_free;
    }
    struct kms_buffer_data in_data = { 0 };
    in_data.buffer = params[INDEX_2].memref.buffer;
    in_data.length = params[INDEX_2].memref.size;
    struct kms_buffer_data out_data = { 0 };
    out_data.buffer = params[INDEX_3].memref.buffer;
    out_data.length = params[INDEX_3].memref.size;
    ret = kms_sign_verify(&key_blob, &param_set, KMS_MODE_VERIFY, &in_data, &out_data);
    if (ret != TEE_SUCCESS) {
        tloge("cmd verify key: verify fail\n");
        goto mem_free;
    }
    params[INDEX_3].memref.size = out_data.length;

mem_free:
    kms_release_key(&in_key, &key_blob);
    free_param_set(&param_set);
    return (int32_t)ret;
}
/*
 * in :operation.params[INDEX_0] key blob or key id
 * in :operation.params[INDEX_1] use key tags
 * in :operation.params[INDEX_2] src data
 * in :operation.params[INDEX_3] mac res data
 */
int32_t kms_cmd_mac_generate(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data key_blob = { 0, NULL };
    struct kms_buffer_data param_set = { 0, NULL };

    struct kms_buffer_data in_key;
    in_key.buffer = params[INDEX_0].memref.buffer;
    in_key.length = params[INDEX_0].memref.size;
    TEE_Result ret = kms_get_key(&in_key, &key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("cmd mac gen: get key fail\n");
        goto mem_free;
    }
    ret = tag_input_to_param_set(params[INDEX_1], &param_set);
    if (ret != TEE_SUCCESS) {
        tloge("cmd mac gen: tag param to datas fail\n");
        goto mem_free;
    }
    struct kms_buffer_data in_data = { 0 };
    in_data.buffer = params[INDEX_2].memref.buffer;
    in_data.length = params[INDEX_2].memref.size;
    struct kms_buffer_data out_data = { 0 };
    out_data.buffer = params[INDEX_3].memref.buffer;
    out_data.length = params[INDEX_3].memref.size;
    ret = kms_mac_generate(&key_blob, &param_set, KMS_MODE_MAC, &in_data, &out_data);
    if (ret != TEE_SUCCESS) {
        tloge("cmd mac gen: mac fail\n");
        goto mem_free;
    }
    params[INDEX_3].memref.size = out_data.length;

mem_free:
    kms_release_key(&in_key, &key_blob);
    free_param_set(&param_set);
    return (int32_t)ret;
}

/*
 * in :operation.params[INDEX_0] keyblob or key id
 * in :operation.params[INDEX_1] mod
 * in :operation.params[INDEX_2] use key tags
 * out:operation.params[INDEX_3] operation handle
 */
int32_t kms_cmd_begin(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data key_blob = { 0, NULL };
    struct kms_buffer_data param_set = { 0, NULL };
    TEE_Result ret;

    struct kms_buffer_data in_key;
    in_key.buffer = params[INDEX_0].memref.buffer;
    in_key.length = params[INDEX_0].memref.size;
    uint32_t kms_mod = *(uint32_t *)params[INDEX_1].memref.buffer;
    if (kms_mod != KMS_MODE_DIGEST) {
        ret = kms_get_key(&in_key, &key_blob);
        if (ret != TEE_SUCCESS) {
            tloge("cmd begin: get key fail\n");
            goto mem_free;
        }
    }
    ret = tag_input_to_param_set(params[INDEX_2], &param_set);
    if (ret != TEE_SUCCESS) {
        tloge("cmd begin: tag param to datas fail\n");
        goto mem_free;
    }
    struct kms_buffer_data opt_handle = { 0 };
    opt_handle.buffer = params[INDEX_3].memref.buffer;
    opt_handle.length = params[INDEX_3].memref.size;
    ret = kms_begin(&key_blob, &param_set, kms_mod, &opt_handle);
    params[INDEX_3].memref.size = opt_handle.length;

mem_free:
    if (kms_mod != KMS_MODE_DIGEST)
        kms_release_key(&in_key, &key_blob);
    free_param_set(&param_set);
    return (int32_t)ret;
}

/*
 * in :operation.params[INDEX_0] mod
 * in :operation.params[INDEX_1] operation handle
 * in :operation.params[INDEX_2] in data
 * out:operation.params[INDEX_3] out data or null
 */
int32_t kms_cmd_update(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data opt_handle = { 0 };
    opt_handle.buffer = params[INDEX_1].memref.buffer;
    opt_handle.length = params[INDEX_1].memref.size;

    struct kms_buffer_data out_data = { 0 };
    out_data.buffer = params[INDEX_3].memref.buffer;
    out_data.length = params[INDEX_3].memref.size;

    struct kms_buffer_data in_data = { 0 };
    in_data.buffer = params[INDEX_2].memref.buffer;
    in_data.length = params[INDEX_2].memref.size;

    uint32_t kms_mod = *(uint32_t *)params[INDEX_0].memref.buffer;
    TEE_Result ret = kms_update(&opt_handle, kms_mod, &in_data, &out_data);
    params[INDEX_3].memref.size = out_data.length;
    return ret;
}
/*
 * in :operation.params[INDEX_0] mod
 * in :operation.params[INDEX_1] operation handle
 * in :operation.params[INDEX_2] in date
 * out:operation.params[INDEX_3] out data or null
 */
int32_t kms_cmd_finish(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data opt_handle = { 0 };
    opt_handle.buffer = params[INDEX_1].memref.buffer;
    opt_handle.length = params[INDEX_1].memref.size;

    struct kms_buffer_data in_data = { 0 };
    in_data.buffer = params[INDEX_2].memref.buffer;
    in_data.length = params[INDEX_2].memref.size;

    struct kms_buffer_data out_data = { 0 };
    out_data.buffer = params[INDEX_3].memref.buffer;
    out_data.length = params[INDEX_3].memref.size;

    uint32_t kms_mod = *(uint32_t *)params[INDEX_0].memref.buffer;
    TEE_Result ret = kms_finish(&opt_handle, kms_mod, &in_data, &out_data);
    params[INDEX_3].memref.size = out_data.length;
    return ret;
}

/*
 * inout : operation.params[INDEX_0] random buffer
 */
int32_t kms_cmd_random(TEE_Param params[CMD_PARAMS_LEN])
{
    TEE_GenerateRandom(params[INDEX_0].memref.buffer, params[INDEX_0].memref.size);
    return TEE_SUCCESS;
}

/*
 * in :operation.params[INDEX_0] key id
 * in :operation.params[INDEX_1] key tags
 * in :operation.params[INDEX_2] key value
 */

int32_t kms_cmd_import_key(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data key_blob = { 0, NULL };
    struct kms_buffer_data param_set = { 0, NULL };
    struct kms_buffer_data in_key;
    in_key.buffer = params[INDEX_2].memref.buffer;
    in_key.length = params[INDEX_2].memref.size;
    TEE_Result ret = tag_input_to_param_set(params[INDEX_1], &param_set);
    if (ret != TEE_SUCCESS) {
        tloge("cmd import key: tag param to datas fail\n");
        goto mem_free;
    }
    ret = kms_import_params_check(&param_set);
    if (ret != TEE_SUCCESS) {
        tloge("cmd import key: tag param check does not pass\n");
        goto mem_free;
    }
    key_blob.length = KEY_BLOB_MAX_SIZE;
    key_blob.buffer = (uint8_t *)TEE_Malloc(key_blob.length, TEE_MALLOC_FILL_ZERO);
    if (key_blob.buffer == NULL) {
        tloge("kms cmd import key: malloc keyblob fail\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto mem_free;
    }
    ret = kms_import_key(&param_set, &in_key, &key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("kms cmd import key: import key fail\n");
        goto mem_free;
    }

    struct kms_buffer_data in_keyid;
    in_keyid.buffer = params[INDEX_0].memref.buffer;
    in_keyid.length = params[INDEX_0].memref.size;
    ret = kms_store_key(&in_keyid, &key_blob, &param_set);
    if (ret != TEE_SUCCESS)
        tloge("kms cmd import key: save key fail\n");

mem_free:
    free_key_blob(&key_blob);
    free_param_set(&param_set);
    return (int32_t)ret;
}

/*
 * in :operation.params[INDEX_0] key id or key blob
 * in :operation.params[INDEX_1] key tags
 * in :operation.params[INDEX_2] target id
 */
int32_t kms_cmd_kdf(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data param_set = { 0, NULL };
    struct kms_buffer_data in_key;
    in_key.buffer = params[INDEX_0].memref.buffer;
    in_key.length = params[INDEX_0].memref.size;
    struct kms_buffer_data key_blob = { 0, NULL };
    TEE_Result res = kms_get_key(&in_key, &key_blob);
    if (res != TEE_SUCCESS) {
        tloge("cmd derivation key: get key fail\n");
        goto mem_free;
    }
    struct kms_buffer_data kdf_key_id;
    kdf_key_id.buffer = params[INDEX_2].memref.buffer;
    kdf_key_id.length = params[INDEX_2].memref.size;
    res = tag_input_to_param_set(params[INDEX_1], &param_set);
    if (res != TEE_SUCCESS) {
        tloge("cmd derivation key: tag param to datas fail\n");
        goto mem_free;
    }
    res = kms_kdf_params_check(&param_set);
    if (res != TEE_SUCCESS) {
        tloge("cmd derivation key: tag param check does not pass\n");
        goto mem_free;
    }
    struct kms_buffer_data kdf_key_blob;
    uint8_t kdf_key_buffer[KEY_BLOB_MAX_SIZE];
    kdf_key_blob.buffer = kdf_key_buffer;
    kdf_key_blob.length = KEY_BLOB_MAX_SIZE;
    res = kms_kdf(&param_set, &kdf_key_id, &key_blob, &kdf_key_blob);
    if (res != TEE_SUCCESS) {
        tloge("cmd derivation key: derivate key fail\n");
        goto mem_free;
    }
    res = kms_store_key(&kdf_key_id, &kdf_key_blob, &param_set);
    if (res != TEE_SUCCESS)
        tloge("cmd derivation key: store key fail\n");
mem_free:
    kms_release_key(&in_key, &key_blob);
    free_param_set(&param_set);
    return (int32_t)res;
}

/*
 * in :operation.params[INDEX_0] key id or keyblob
 * in :operation.params[INDEX_1] in key params
 * out:operation.params[INDEX_2] out key params
 */
int32_t kms_cmd_getmeta(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data out_param_set;
    out_param_set.buffer = params[INDEX_2].memref.buffer;
    out_param_set.length = params[INDEX_2].memref.size;
    struct kms_buffer_data in_key;
    in_key.buffer = params[INDEX_0].memref.buffer;
    in_key.length = params[INDEX_0].memref.size;

    struct kms_buffer_data in_param_set = { 0, NULL };
    TEE_Result ret = tag_input_to_param_set(params[INDEX_1], &in_param_set);
    if (ret != TEE_SUCCESS) {
        tloge("kms cmd getmeta: tag param to datas fail\n");
        goto mem_free;
    }

    ret = kms_getmeta(&in_key, &in_param_set, &out_param_set);
    if (ret != TEE_SUCCESS) {
        tloge("kms cmd getmeta: get key meta fail\n");
        goto mem_free;
    }

    ret = kms_getmeta_params_check(&out_param_set);
    if (ret != TEE_SUCCESS)
        tloge("kms cmd getmeta: tag param check does not pass\n");

mem_free:
    free_param_set(&in_param_set);
    /* if get key failed, output params.length equal zero. */
    params[INDEX_2].memref.size = out_param_set.length;
    return (int32_t)ret;
}

/*
 * in :operation.params[INDEX_0] key blob or key id
 * in :operation.params[INDEX_1] key tags
 * out:operation.params[INDEX_2] key value
 */
int32_t kms_cmd_export_key(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data key_blob = { 0, NULL };
    struct kms_buffer_data param_set = { 0, NULL };

    struct kms_buffer_data in_key;
    in_key.buffer = params[INDEX_0].memref.buffer;
    in_key.length = params[INDEX_0].memref.size;

    TEE_Result ret = kms_get_key(&in_key, &key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("cmd export key: get key fail\n");
        goto mem_free;
    }
    struct kms_buffer_data out_key;
    out_key.buffer = params[INDEX_2].memref.buffer;
    out_key.length = params[INDEX_2].memref.size;
    ret = tag_input_to_param_set(params[INDEX_1], &param_set);
    if (ret != TEE_SUCCESS) {
        tloge("cmd export key: tag param to datas fail\n");
        goto mem_free;
    }
    ret = kms_export_key(&param_set, &out_key, &key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("kms cmd export key: export key fail\n");
        goto mem_free;
    }
    params[INDEX_2].memref.size = out_key.length;

mem_free:
    kms_release_key(&in_key, &key_blob);
    free_param_set(&param_set);
    return (int32_t)ret;
}
/*
 * out:operation.params[INDEX_0] key blob or key id
 * in :operation.params[INDEX_1] key tags
 */
int32_t kms_cmd_delete_key(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data key_blob = { 0, NULL };
    struct kms_buffer_data param_set = { 0, NULL };

    struct kms_buffer_data in_key;
    in_key.buffer = params[INDEX_0].memref.buffer;
    in_key.length = params[INDEX_0].memref.size;
    TEE_Result ret = kms_get_key(&in_key, &key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("cmd delete key: get key fail\n");
        goto mem_free;
    }
    ret = tag_input_to_param_set(params[INDEX_1], &param_set);
    if (ret != TEE_SUCCESS) {
        tloge("cmd delete key: tag param to datas fail\n");
        goto mem_free;
    }
    ret = kms_delete(&param_set, &key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("cmd delete key : params for delete is invalid\n");
        goto mem_free;
    }
    ret = kms_delete_key(&in_key);
    if (ret != TEE_SUCCESS)
        tloge("cmd delete key failed\n");

mem_free:
    kms_release_key(&in_key, &key_blob);
    free_param_set(&param_set);
    return (int32_t)ret;
}
/*
 * in :operation.params[INDEX_0] opt handle
 */
int32_t kms_cmd_abort(TEE_Param params[CMD_PARAMS_LEN])
{
    struct kms_buffer_data opt_handle = { 0 };
    opt_handle.buffer = params[INDEX_0].memref.buffer;
    opt_handle.length = params[INDEX_0].memref.size;
    return kms_abort(&opt_handle);
}
