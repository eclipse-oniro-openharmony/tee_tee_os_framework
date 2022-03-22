/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Safety operator
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#include "crypto_operation.h"
#include "securec.h"
#include "gp_api_adaptation.h"
#include "kms_tag_api.h"
#include "kms_key_storage.h"
#include "kms_params_check.h"
#include "kdf.h"
#include "tee_log.h"

/* key blob struct
 * ---kms key base info:kms_key_base_info
 * --------------------------------------
 * ---gp key base info(gp_key_base_info) | hms key base info (kms not have hsm store struct)
 * ---gp key encrypto by root key        | hms key encrypto by hms key
 */
static TEE_Result kms_key_blob_mac(const struct kms_buffer_data *param_set, uint32_t mod,
    const struct kms_buffer_data *key_blob)
{
    TEE_Result ret;
    struct kms_buffer_data derived_factor = { 0 };
    /* it should not null when IAM can approve appid for kms */
    ret = get_key_param(&derived_factor, KMS_TAG_APP_ID, param_set);
    if (ret != 0)
        tlogd("key blob mac: not appid\n");

    struct kms_buffer_data in_data;
    struct kms_buffer_data out_data;
    in_data.buffer = key_blob->buffer + KEY_BLOB_MAC_LEN;
    in_data.length = key_blob->length - KEY_BLOB_MAC_LEN;

    if (mod == KMS_BLOB_MAC_MODE_GENERATE) {
        out_data.buffer = key_blob->buffer;
        out_data.length = KEY_BLOB_MAC_LEN;
        ret = key_blob_mac(&derived_factor, &in_data, &out_data);
        if (ret != TEE_SUCCESS)
            tloge("key blob mac: hmac for key fail\n");
    } else {
        uint8_t mac[KEY_BLOB_MAC_LEN] = { 0 };
        out_data.buffer = mac;
        out_data.length = KEY_BLOB_MAC_LEN;
        ret = key_blob_mac(&derived_factor, &in_data, &out_data);
        if (ret != TEE_SUCCESS) {
            tloge("key blob mac: keyblob mac check fail\n");
            return ret;
        }
        if (TEE_MemCompare(mac, key_blob->buffer, KEY_BLOB_MAC_LEN) != 0) {
            tloge("key blob mac: mac check fail\n");
            ret = TEE_ERROR_ACCESS_DENIED;
        }
    }
    return ret;
}

static TEE_Result kms_crypto_keyblob(struct kms_buffer_data *key_blob, uint32_t tee_mode)
{
    struct kms_buffer_data out_data;
    uint8_t key_buffer[KEY_BLOB_MAX_SIZE] = { 0 };
    out_data.buffer = key_buffer;
    out_data.length = KEY_BLOB_MAX_SIZE;
    TEE_Result ret = key_blob_crypto(key_blob, tee_mode, &out_data);
    if (ret != TEE_SUCCESS) {
        tloge("kms key blob crypto fail\n");
        return ret;
    }
    struct kms_key_base_info *key_base_info = (struct kms_key_base_info *)(key_blob->buffer);
    errno_t rc = memcpy_s(key_base_info->keyblob_body, key_blob->length - sizeof(*key_base_info),
        out_data.buffer, out_data.length);
    if (rc != EOK) {
        tloge("kms crypto key blob memory copy fail\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (UINT32_MAX - out_data.length < sizeof(*key_base_info)) {
        tloge("integer check failed\n");
        return TEE_ERROR_GENERIC;
    }
    key_base_info->total_length = out_data.length + sizeof(*key_base_info);
    key_blob->length = key_base_info->total_length;
    return TEE_SUCCESS;
}

/*
 * 1. check key blob mac
 * 2. get gp_key_blob block if gp_key_blob != NULL
 * 3. get param_set block in key_blob if param_in_blob != NULL
 */
static TEE_Result keyblob_pre_proc(const struct kms_buffer_data *param_set, struct kms_buffer_data *key_blob,
    struct kms_buffer_data *gp_key_blob, struct kms_buffer_data *param_in_blob)
{
    if (key_blob == NULL || key_blob->buffer == NULL || key_blob->length < sizeof(struct kms_key_base_info)) {
        tloge("keyblob pre proc: input is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    TEE_Result ret = kms_key_blob_mac(param_set, KMS_BLOB_MAC_MODE_CHECK, key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("keyblob pre proc: mac check fail\n");
        return ret;
    }
    struct kms_key_base_info *key_base_info = (struct kms_key_base_info *)key_blob->buffer;
    if (key_base_info->version == KMS_KEY_VERSION_1) {
        if (gp_key_blob != NULL) {
            gp_key_blob->buffer = key_blob->buffer + sizeof(*key_base_info);
            gp_key_blob->length = key_blob->length - sizeof(*key_base_info);
        }
        return TEE_SUCCESS;
    }
    ret = kms_crypto_keyblob(key_blob, TEE_MODE_DECRYPT);
    if (ret != TEE_SUCCESS) {
        tloge("keyblob pre proc: dec keyblob fail\n");
        return ret;
    }
    if (gp_key_blob != NULL) {
        gp_key_blob->buffer = key_blob->buffer + key_base_info->gp_key_offset;
        gp_key_blob->length = key_base_info->gp_key_length;
    }
    if (param_in_blob != NULL) {
        param_in_blob->buffer = key_blob->buffer + key_base_info->params_offset;
        param_in_blob->length = key_base_info->params_length;
    }
    return ret;
}

static TEE_Result fill_key_base_info(const struct kms_buffer_data *param_set, struct kms_key_base_info *bi)
{
    uint32_t key_type, key_size;
    TEE_Result ret = get_key_param(&key_type, KMS_TAG_KEY_TYPE, param_set);
    if (ret != 0) {
        tloge("get key type failed!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = get_key_param(&key_size, KMS_TAG_KEY_SIZE, param_set);
    if (ret != 0) {
        tloge("get key size failed!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    bi->key_type = key_type;
    bi->key_size = key_size;
    bi->version = KMS_KEY_VERSION_2;
    bi->magic = MAGIC;
    return TEE_SUCCESS;
}

static TEE_Result kms_add_key_paramset(const struct kms_buffer_data *param_set, struct kms_buffer_data *params_blob)
{
    errno_t rc;
    struct kms_buffer_data filtered_param_set;
    filtered_param_set.length = param_set->length;
    filtered_param_set.buffer = (uint8_t *)TEE_Malloc(filtered_param_set.length, TEE_MALLOC_FILL_ZERO);
    if (filtered_param_set.buffer == NULL) {
        tloge("malloc filtered param set failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    (void)memcpy_s(filtered_param_set.buffer, filtered_param_set.length, param_set->buffer, param_set->length);
    TEE_Result ret = kms_persistent_tag_filter_in(&filtered_param_set);
    if (ret != TEE_SUCCESS) {
        tloge("filter persistent tags failed.\n");
        goto add_param_failed;
    }

    rc = memcpy_s(params_blob->buffer, params_blob->length, filtered_param_set.buffer, filtered_param_set.length);
    if (rc != EOK) {
        tloge("kms add key paramset fail\n");
        ret = TEE_ERROR_GENERIC;
    }

add_param_failed:
    if (filtered_param_set.buffer != NULL) {
        TEE_Free(filtered_param_set.buffer);
        filtered_param_set.buffer = NULL;
    }

    params_blob->length = filtered_param_set.length;
    return ret;
}

TEE_Result kms_create_key(const struct kms_buffer_data *param_set, struct kms_buffer_data *key_blob)
{
    bool check = (param_set == NULL || param_set->buffer == NULL || key_blob == NULL || key_blob->buffer == NULL ||
        key_blob->length < sizeof(struct kms_key_base_info));
    if (check) {
        tloge("kms create key : input is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    struct kms_key_base_info *key_base_info = (struct kms_key_base_info *)key_blob->buffer;
    TEE_Result ret = fill_key_base_info(param_set, key_base_info);
    if (ret != TEE_SUCCESS) {
        tloge("kms create key : fill key type key size fail\n");
        return ret;
    }
    struct kms_buffer_data next_blob;
    key_base_info->gp_key_offset = sizeof(*key_base_info);
    next_blob.buffer = key_blob->buffer + key_base_info->gp_key_offset;
    next_blob.length = key_blob->length - key_base_info->gp_key_offset;
    ret = gp_create_key(param_set, &next_blob);
    if (ret != TEE_SUCCESS) {
        tloge("kms create key: gp create key fail\n");
        return ret;
    }
    key_base_info->gp_key_length = next_blob.length;
    key_base_info->params_offset = key_base_info->gp_key_offset + key_base_info->gp_key_length;
    if (key_blob->length < key_base_info->params_offset) {
        tloge("integer check failed\n");
        return TEE_ERROR_GENERIC;
    }
    next_blob.buffer = key_blob->buffer + key_base_info->params_offset;
    next_blob.length = key_blob->length - key_base_info->params_offset;
    ret = kms_add_key_paramset(param_set, &next_blob);
    if (ret != TEE_SUCCESS) {
        tloge("kms create key: add key params set fail\n");
        return ret;
    }
    key_base_info->params_length = next_blob.length;
    key_base_info->total_length = key_base_info->params_offset + key_base_info->params_length;
    ret = kms_crypto_keyblob(key_blob, TEE_MODE_ENCRYPT);
    if (ret != TEE_SUCCESS) {
        tloge("kms create key: crypto key blob fail\n");
        return ret;
    }
    ret = kms_key_blob_mac(param_set, KMS_BLOB_MAC_MODE_GENERATE, key_blob);
    if (ret != TEE_SUCCESS)
        tloge("kms create key: key blob mac fail\n");
    return ret;
}

TEE_Result kms_crypto(struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data)
{
    struct kms_buffer_data gp_key_blob = { 0 };
    TEE_Result ret = keyblob_pre_proc(param_set, key_blob, &gp_key_blob, NULL);
    if (ret != TEE_SUCCESS) {
        tloge("kms crypto : input is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    ret = gp_crypto(&gp_key_blob, param_set, kms_mod, in_data, out_data);
    if (ret != TEE_SUCCESS)
        tloge("kms crypto: gp crypto fail\n");
    return ret;
}

TEE_Result kms_digest(const struct kms_buffer_data *param_set, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data)
{
    TEE_Result ret = gp_digest(param_set, in_data, out_data);
    if (ret != TEE_SUCCESS)
        tloge("kms digest: gp digest fail\n");
    return ret;
}

TEE_Result kms_sign_verify(struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data)
{
    struct kms_buffer_data gp_key_blob = { 0 };
    TEE_Result ret = keyblob_pre_proc(param_set, key_blob, &gp_key_blob, NULL);
    if (ret != TEE_SUCCESS) {
        tloge("kms sign verify : input is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    ret = gp_sign_verify(&gp_key_blob, param_set, kms_mod, in_data, out_data);
    if (ret != TEE_SUCCESS) {
        tloge("kms sign verify: sign or verify fail\n");
        return ret;
    }
    return ret;
}

TEE_Result kms_mac_generate(struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data)
{
    struct kms_buffer_data gp_key_blob = { 0 };
    TEE_Result ret = keyblob_pre_proc(param_set, key_blob, &gp_key_blob, NULL);
    if (ret != TEE_SUCCESS) {
        tloge("kms mac gen : input is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    ret = gp_mac_generate(&gp_key_blob, param_set, kms_mod, in_data, out_data);
    if (ret != TEE_SUCCESS)
        tloge("kms mac generate: mac generate fail\n");
    return ret;
}
TEE_Result kms_begin(struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, struct kms_buffer_data *opt_handle)
{
    TEE_Result ret;
    struct kms_buffer_data gp_key_blob = { 0 };
    if (kms_mod != KMS_MODE_DIGEST) {
        ret = keyblob_pre_proc(param_set, key_blob, &gp_key_blob, NULL);
        if (ret != TEE_SUCCESS) {
            tloge("kms begin : input is invalid\n");
            return TEE_ERROR_READ_DATA;
        }
    }

    ret = gp_begin(&gp_key_blob, param_set, kms_mod, opt_handle);
    if (ret != TEE_SUCCESS)
        tloge("kms begin: mod %u fail\n", kms_mod);
    return ret;
}
TEE_Result kms_update(const struct kms_buffer_data *opt_handle, uint32_t kms_mod, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data)
{
    TEE_Result ret = gp_update(opt_handle, kms_mod, in_data, out_data);
    if (ret != TEE_SUCCESS) {
        tloge("kms update: update fail\n");
        gp_abort(opt_handle);
    }
    return ret;
}
TEE_Result kms_finish(const struct kms_buffer_data *opt_handle, uint32_t kms_mod, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data)
{
    TEE_Result ret = gp_finish(opt_handle, kms_mod, in_data, out_data);
    if (ret != TEE_SUCCESS) {
        tloge("kms finish: gp finish fail\n");
        gp_abort(opt_handle);
    }
    return ret;
}

TEE_Result kms_getmeta(const struct kms_buffer_data *in_key, const struct kms_buffer_data *in_param_set,
    struct kms_buffer_data *out_param_set)
{
    bool condition = (in_key == NULL || in_key->buffer == NULL || in_param_set == NULL ||
                      in_param_set->buffer == NULL || out_param_set == NULL || out_param_set->buffer == NULL);
    if (condition) {
        tloge("kms getmeta: input is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    struct kms_buffer_data key_blob = { 0, NULL };
    TEE_Result ret = kms_get_key(in_key, &key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("kms getmeta: input key id does not exist!\n");
        out_param_set->length = 0;
        goto mem_free;
    }

    struct kms_buffer_data gp_key_blob = { 0, NULL };
    ret = keyblob_pre_proc(in_param_set, &key_blob, &gp_key_blob, NULL);
    if (ret != TEE_SUCCESS) {
        tloge("kms getmeta: input keyblob is invalid\n");
        goto mem_free;
    }

    /* pack key type, key size into out_param_set */
    uint32_t total_length = sizeof(uint32_t) + sizeof(struct kms_param_t) + sizeof(struct kms_param_t);
    if (out_param_set->length < total_length) {
        tloge("out param length is too small!\n");
        goto mem_free;
    }
    struct kms_param_t *params = (struct kms_param_t *)((uint8_t *)out_param_set->buffer + sizeof(uint32_t));
    struct kms_key_base_info *bi = (struct kms_key_base_info *)(key_blob.buffer);
    uint32_t index = 0;
    params[index].tag = KMS_TAG_KEY_TYPE;
    params[index++].data.integer = bi->key_type;
    params[index].tag = KMS_TAG_KEY_SIZE;
    params[index++].data.integer = bi->key_size;
    *(uint32_t *)out_param_set->buffer = index;
    out_param_set->length = total_length;

mem_free:
    kms_release_key(in_key, &key_blob);
    return ret;
}

TEE_Result kms_import_key(const struct kms_buffer_data *param_set, const struct kms_buffer_data *in_key,
    struct kms_buffer_data *key_blob)
{
    bool check = (param_set == NULL || param_set->buffer == NULL || key_blob == NULL || key_blob->buffer == NULL ||
        key_blob->length < sizeof(struct kms_key_base_info));
    if (check) {
        tloge("kms import key : input is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    struct kms_key_base_info *key_base_info = (struct kms_key_base_info *)key_blob->buffer;
    TEE_Result ret = fill_key_base_info(param_set, key_base_info);
    if (ret != TEE_SUCCESS) {
        tloge("kms import key : fill key type key size fail\n");
        return ret;
    }
    struct kms_buffer_data next_blob;
    key_base_info->gp_key_offset = sizeof(*key_base_info);
    next_blob.buffer = key_blob->buffer + key_base_info->gp_key_offset;
    next_blob.length = key_blob->length - key_base_info->gp_key_offset;
    ret = gp_import_key(param_set, in_key, &next_blob);
    if (ret != TEE_SUCCESS) {
        tloge("kms import key: gp import key fail\n");
        return ret;
    }
    key_base_info->gp_key_length = next_blob.length;
    key_base_info->params_offset = key_base_info->gp_key_offset + key_base_info->gp_key_length;
    next_blob.buffer = key_blob->buffer + key_base_info->params_offset;
    next_blob.length = key_blob->length - key_base_info->params_offset;
    ret = kms_add_key_paramset(param_set, &next_blob);
    if (ret != TEE_SUCCESS) {
        tloge("kms import key: add key params set fail\n");
        return ret;
    }
    key_base_info->params_length = next_blob.length;
    key_base_info->total_length = key_base_info->params_offset + key_base_info->params_length;
    ret = kms_crypto_keyblob(key_blob, TEE_MODE_ENCRYPT);
    if (ret != TEE_SUCCESS) {
        tloge("kms import key: crypto key blob fail\n");
        return ret;
    }
    ret = kms_key_blob_mac(param_set, KMS_BLOB_MAC_MODE_GENERATE, key_blob);
    if (ret != TEE_SUCCESS)
        tloge("kms import key: mac fail\n");
    return ret;
}

static TEE_Result check_derivable(struct kms_buffer_data *key_blob)
{
    struct kms_key_base_info *bi = (struct kms_key_base_info *)key_blob->buffer;
    struct kms_buffer_data param_set;
    param_set.buffer = (uint8_t *)key_blob->buffer + bi->params_offset;
    param_set.length = bi->params_length;
    /* check KMS_TAG_DERIVABLE */
    bool key_derivable = false;
    TEE_Result ret = get_key_param(&key_derivable, KMS_TAG_DERIVABLE, &param_set);
    if (ret != TEE_SUCCESS) {
        tloge("check whether deriable: in key is underivable\n");
        return KMS_ERROR_UNSUPPORTED_KDF;
    }
    if (key_derivable == false)
        return KMS_ERROR_UNSUPPORTED_KDF;
    /* check KEY_TYPE */
    uint32_t key_type;
    ret = get_key_param(&key_type, KMS_TAG_KEY_TYPE, &param_set);
    if (ret != 0) {
        tloge("check whether deriable: failed to get key type\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    switch (key_type) {
    case KMS_KEY_TYPE_AES:
    case KMS_KEY_TYPE_HMAC:
    case KMS_KEY_TYPE_GENERIC:
        ret = TEE_SUCCESS;
        break;
    default:
        tloge("kdf check derivable: unsupport derivation key type 0x%x\n", key_type);
        ret = TEE_ERROR_BAD_PARAMETERS;
        break;
    }
    return ret;
}

TEE_Result kms_kdf(const struct kms_buffer_data *param_set, const struct kms_buffer_data *target_key,
                   struct kms_buffer_data *key_blob, struct kms_buffer_data *kdf_key_blob)
{
    bool condition = (param_set == NULL || param_set->buffer == NULL || key_blob == NULL ||
                      key_blob->buffer == NULL || target_key == NULL || target_key->buffer == NULL ||
                      key_blob->length < sizeof(struct kms_key_base_info));
    if (condition) {
        tloge("kms derivation key: input is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    struct kms_buffer_data gp_key_blob = { 0, NULL };
    TEE_Result ret = keyblob_pre_proc(param_set, key_blob, &gp_key_blob, NULL);
    if (ret != TEE_SUCCESS) {
        tloge("kms derivation key: input is invalid\n");
        return KMS_ERROR_INVALID_KEY_BLOB;
    }
    ret = check_derivable(key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("kms_kdf: input key is underiable!\n");
        return KMS_ERROR_UNSUPPORTED_KDF;
    }
    uint32_t key_size;
    ret = get_key_param(&key_size, KMS_TAG_KEY_SIZE, param_set);
    if (ret != TEE_SUCCESS) {
        tloge("kms_kdf: get key size failed\n");
        return ret;
    }
    if (key_size % KMS_BYTE_TO_BITS != 0) {
        tloge("kms_kdf: input key size invalid\n");
        return KMS_ERROR_UNSUPPORTED_KEY_SIZE;
    }
    TEE_ObjectHandle key_obj = NULL;
    uint8_t kdf_data[BUFFER_DATA_MAX_SIZE] = { 0 };
    struct kms_buffer_data kdf_key = { key_size / KMS_BYTE_TO_BITS, kdf_data };
    ret = gp_kdf_load_key(param_set, &key_obj, &gp_key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("kms derivation key: load key obj failed\n");
        return ret;
    }
    ret = kdf_implement_algo(param_set, key_obj, &kdf_key);
    if (ret != TEE_SUCCESS) {
        tloge("kms derivation key: implement kdf algo failed\n");
        return ret;
    }
    ret = kms_import_key(param_set, &kdf_key, kdf_key_blob);
    if (ret != TEE_SUCCESS)
        tloge("kms derivation key: import key failed\n");
    return ret;
}

static TEE_Result check_export_permission(const struct kms_buffer_data *param_set,
    const struct kms_buffer_data *param_in_blob)
{
    uint32_t key_type;
    TEE_Result ret = get_key_param(&key_type, KMS_TAG_KEY_TYPE, param_set);
    if (ret != TEE_SUCCESS) {
        tloge("check export permission: get key type failed\n");
        return ret;
    }
    bool check = ((key_type == KMS_KEY_TYPE_RSA_PUBLIC) || (key_type == KMS_KEY_TYPE_SM2_PUBLIC) ||
        (key_type == KMS_KEY_TYPE_ECDSA_PUBLIC) || (key_type == KMS_KEY_TYPE_ED25519_PUBLIC));
    if (check)
        return TEE_SUCCESS; /* asymmetric public key need not check permission */
    struct kms_buffer_data app_proc_name = { 0, NULL };
    ret = get_key_param(&app_proc_name, KMS_TAG_APP_PROC_NAME, param_set);
    if (ret != TEE_SUCCESS) {
        tloge("check export permission: get app proc name failed\n");
        return ret;
    }
    ret = match_tag_in_param_set(KMS_TAG_EXPORT_PROC_NAME, app_proc_name.buffer, app_proc_name.length, param_in_blob);
    if (ret != TEE_SUCCESS) {
        tloge("check export permission: not in permission group\n");
        return TEE_ERROR_ACCESS_DENIED;
    }
    return TEE_SUCCESS;
}

TEE_Result kms_export_key(const struct kms_buffer_data *param_set, struct kms_buffer_data *out_key,
    struct kms_buffer_data *key_blob)
{
    bool check = (param_set == NULL || param_set->buffer == NULL || key_blob == NULL || key_blob->buffer == NULL ||
        key_blob->length < sizeof(struct kms_key_base_info));
    if (check) {
        tloge("kms export key : input is invalid\n");
        return TEE_ERROR_READ_DATA;
    }

    struct kms_buffer_data gp_key_blob = { 0, NULL };
    struct kms_buffer_data param_in_blob = { 0, NULL };
    TEE_Result ret = keyblob_pre_proc(param_set, key_blob, &gp_key_blob, &param_in_blob);
    if (ret != TEE_SUCCESS) {
        tloge("kms export key : input is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    ret = check_export_permission(param_set, &param_in_blob);
    if (ret != TEE_SUCCESS) {
        tloge("kms export key: check permission failed\n");
        return ret;
    }
    ret = gp_export_key(param_set, out_key, &gp_key_blob);
    if (ret != TEE_SUCCESS)
        tloge("kms export key: gp fail\n");
    return ret;
}

static TEE_Result check_delete_permission(const struct kms_buffer_data *param_set,
    const struct kms_buffer_data *param_in_blob)
{
    if (!tag_exists_in_param_set(KMS_TAG_DELETE_PROC_NAME, param_in_blob))
        return TEE_SUCCESS; /* key need not check permission */
    struct kms_buffer_data app_proc_name = { 0, NULL };
    TEE_Result ret = get_key_param(&app_proc_name, KMS_TAG_APP_PROC_NAME, param_set);
    if (ret != TEE_SUCCESS) {
        tloge("check delete permission: get app proc name failed\n");
        return ret;
    }
    ret = match_tag_in_param_set(KMS_TAG_DELETE_PROC_NAME, app_proc_name.buffer, app_proc_name.length, param_in_blob);
    if (ret != TEE_SUCCESS) {
        tloge("check delete permission: not in permission group\n");
        return TEE_ERROR_ACCESS_DENIED;
    }
    return TEE_SUCCESS;
}

TEE_Result kms_delete(const struct kms_buffer_data *param_set, struct kms_buffer_data *key_blob)
{
    bool check = (param_set == NULL || param_set->buffer == NULL || key_blob == NULL || key_blob->buffer == NULL ||
        key_blob->length < sizeof(struct kms_key_base_info));
    if (check) {
        tloge("kms delete key: input is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    /* only can have appid or app proc name */
    uint32_t param_count = 0;
    if (tag_exists_in_param_set(KMS_TAG_APP_ID, param_set))
        param_count++;
    if (tag_exists_in_param_set(KMS_TAG_APP_PROC_NAME, param_set))
        param_count++;
    if (param_count != (*(uint32_t *)param_set->buffer)) {
        tloge("kms delete key: received tags error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct kms_buffer_data param_in_blob = { 0, NULL };
    TEE_Result ret = keyblob_pre_proc(param_set, key_blob, NULL, &param_in_blob);
    if (ret != TEE_SUCCESS) {
        tloge("kms delete key: input keyblob check failed\n");
        return TEE_ERROR_READ_DATA;
    }
    /* since key blob version 2 need check delete permission */
    if (param_in_blob.buffer != NULL) {
        ret = check_delete_permission(param_set, &param_in_blob);
        if (ret != TEE_SUCCESS)
            tloge("kms delete key: check permission failed\n");
    }
    return ret;
}

TEE_Result kms_abort(const struct kms_buffer_data *opt_handle)
{
    if (opt_handle == NULL || opt_handle->buffer == NULL) {
        tloge("kms abort: input is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    gp_abort(opt_handle);
    return TEE_SUCCESS;
}
