/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:kms key storage functions
 * Create: 2021-12-01
 */
#include "kms_key_storage.h"
#include "securec.h"
#include "tee_log.h"
#include "kms_tag_api.h"
#include "kms_pub_def.h"
#include "kms_file_ops.h"
#include "volatile_key.h"
#include "invoke_check.h"

TEE_Result kms_store_key(const struct kms_buffer_data *key_id, const struct kms_buffer_data *key_blob,
    const struct kms_buffer_data *param_set)
{
    bool check_param = ((key_id == NULL) || (key_id->buffer == NULL) || (key_id->length == 0) ||
        (key_blob == NULL) || (key_blob->buffer == NULL) || (key_blob->length == 0) ||
        (param_set == NULL) || (param_set->buffer == NULL) || (param_set->length == 0));
    if (check_param) {
        tloge("kms store key: invalid params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    char *key_name = (char *)key_id->buffer;
    if (strnlen(key_name, key_id->length) != (key_id->length - 1)) {
        tloge("kms store key: invalid key id\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t batch_num;
    bool is_overwrite = ((auth_vkms() && (get_key_param(&batch_num, KMS_TAG_BATCH_NUM, param_set) == TEE_SUCCESS)) ?
        true : false);

    bool is_volatile = false;
    if (get_key_param(&is_volatile, KMS_TAG_VOLATILE_KEY, param_set) != TEE_SUCCESS)
        is_volatile = false;
    if (is_volatile) {
        if (is_overwrite && (get_volatile_keyblob(key_name, NULL) == TEE_SUCCESS)) {
            TEE_Result ret = del_volatile_keyblob(key_name);
            if (ret != TEE_SUCCESS) {
                tloge("kms store key: key del volatile key %s fail\n", key_name);
                return ret;
            }
        }
        return insert_volatile_keyblob(key_name, key_blob);
    }
    if ((!is_overwrite) && (kms_file_access(key_name) == TEE_SUCCESS)) {
        tloge("kms store key: key %s existed\n", key_name);
        return TEE_ERROR_ACCESS_CONFLICT;
    }
    if (is_overwrite)
        tlogi("writing %s, overwrite %d\n", key_name, is_overwrite);
    return kms_file_write(key_name, key_blob->buffer, key_blob->length);
}

TEE_Result kms_access_key(const struct kms_buffer_data *key_id)
{
    bool check_param = (key_id == NULL) || (key_id->buffer == NULL) || (key_id->length == 0);
    if (check_param) {
        tloge("kms access key: invalid params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    char *key_name = (char *)key_id->buffer;
    if (strnlen(key_name, key_id->length) != (key_id->length - 1)) {
        tloge("kms access key: invalid key id\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret = kms_file_access(key_name);
    if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
        ret = get_volatile_keyblob(key_name, NULL);
        if (ret == TEE_ERROR_ITEM_NOT_FOUND)
            ret = (TEE_Result)KMS_ERROR_KEY_ID_NOT_PRESENT;
    }
    return ret;
}

TEE_Result kms_get_key(const struct kms_buffer_data *id_or_blob, struct kms_buffer_data *key_blob)
{
    bool check_param = (id_or_blob == NULL) || (id_or_blob->buffer == NULL) || (id_or_blob->length == 0);
    if (check_param) {
        tloge("kms get key: invalid params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (id_or_blob->length > MAX_KEY_ID_LEN) {
        key_blob->buffer = id_or_blob->buffer;
        key_blob->length = id_or_blob->length;
        return TEE_SUCCESS;
    }
    char *key_id = (char *)id_or_blob->buffer;
    if (strnlen(key_id, id_or_blob->length) != (id_or_blob->length - 1)) {
        tloge("kms get key: invalid key id\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    key_blob->length = KEY_BLOB_MAX_SIZE;
    key_blob->buffer = (uint8_t *)TEE_Malloc(key_blob->length, TEE_MALLOC_FILL_ZERO);
    if (key_blob->buffer == NULL) {
        tloge("kms get key: malloc key blob fail\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_Result ret = kms_file_read(key_id, key_blob->buffer, &(key_blob->length));
    if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
        ret = get_volatile_keyblob(key_id, key_blob);
        if (ret == TEE_ERROR_ITEM_NOT_FOUND)
            ret = (TEE_Result)KMS_ERROR_KEY_ID_NOT_PRESENT;
    }
    if (ret != TEE_SUCCESS)
        tloge("kms get key: read key fail 0x%x\n", ret);
    return ret;
}

void kms_release_key(const struct kms_buffer_data *id_or_blob, struct kms_buffer_data *key_blob)
{
    bool check_param = (id_or_blob == NULL) || (id_or_blob->buffer == NULL) || (id_or_blob->length == 0);
    if (check_param)
        return;
    bool need_release = (id_or_blob->length <= MAX_KEY_ID_LEN) && (key_blob != NULL) &&
        (key_blob->buffer != NULL) && (key_blob->length != 0);
    if (need_release) {
        (void)memset_s(key_blob->buffer, key_blob->length, 0, key_blob->length);
        TEE_Free(key_blob->buffer);
        key_blob->buffer = NULL;
        key_blob->length = 0;
    }
}

TEE_Result kms_delete_key(const struct kms_buffer_data *id_or_blob)
{
    bool check_param = (id_or_blob == NULL) || (id_or_blob->buffer == NULL) || (id_or_blob->length == 0);
    if (check_param) {
        tloge("kms delete key: invalid params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (id_or_blob->length > MAX_KEY_ID_LEN)
        return TEE_SUCCESS;
    char* key_id = (char *)id_or_blob->buffer;
    if (strnlen(key_id, id_or_blob->length) != (id_or_blob->length - 1)) {
        tloge("kms delete key: invalid key id\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (get_volatile_keyblob(key_id, NULL) == TEE_SUCCESS)
        return del_volatile_keyblob(key_id);
    return kms_file_remove(key_id);
}
