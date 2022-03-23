/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: kms tag check
 * Create: 2021-12-14
 */

#include "kms_params_check.h"
#include "tee_log.h"
#include "kms_pub_def.h"
#include "securec.h"

/* global tag white list */
static const enum kms_tags g_tag_white_list[] = { KMS_TAG_INVALID, KMS_TAG_KEY_TYPE, KMS_TAG_KEY_SIZE,
    KMS_TAG_OPERATION_ALGORITHM, KMS_TAG_TA_DATA, KMS_TAG_EC_CURVE, KMS_TAG_PADDING, KMS_TAG_RSA_PUBLIC_EXPONENT,
    KMS_TAG_HASH_TYPE, KMS_TAG_HUK, KMS_TAG_HUK, KMS_TAG_IV, KMS_TAG_APP_ID, KMS_TAG_GCM_MAC_LEN, KMS_TAG_ITER_NUM,
    KMS_TAG_GCM_AAD, KMS_TAG_OBJ_TYPE, KMS_TAG_KEY_ID, KMS_TAG_KEY_CTR, KMS_TAG_KEY_FLAGS, KMS_TAG_CLRTEXT_EXPORTABLE,
    KMS_TAG_DERIVABLE, KMS_TAG_VOLATILE_KEY, KMS_TAG_PARENT_KEY_ID, KMS_TAG_CREATE_TIME, KMS_TAG_ORIGIN,
    KMS_TAG_KDF_TYPE, KMS_TAG_BATCH_NUM, KMS_TAG_BATCH_KEY_ID_IN_LIST, KMS_TAG_KDF_LABEL, KMS_TAG_KDF_CONTEXT,
    KMS_TAG_KEY_ID_RANDOM_SUFFIX, KMS_TAG_TASK_ID, KMS_TAG_VIN, KMS_TAG_ECU_CTR, KMS_TAG_BUFF_SIZE,
    KMS_TAG_APP_PROC_NAME, KMS_TAG_EXPORT_PROC_NAME, KMS_TAG_DELETE_PROC_NAME, KMS_TAG_KEY_FORMAT };

/* global persistent tag list */
static const enum kms_tags g_persistent_tag_filter_in_list[] = { KMS_TAG_KEY_TYPE, KMS_TAG_KEY_SIZE, KMS_TAG_EC_CURVE,
    KMS_TAG_RSA_PUBLIC_EXPONENT, KMS_TAG_OBJ_TYPE, KMS_TAG_KEY_ID, KMS_TAG_KEY_CTR, KMS_TAG_KEY_FLAGS,
    KMS_TAG_CLRTEXT_EXPORTABLE, KMS_TAG_DERIVABLE, KMS_TAG_VOLATILE_KEY, KMS_TAG_APP_ID, KMS_TAG_PARENT_KEY_ID,
    KMS_TAG_CREATE_TIME, KMS_TAG_ORIGIN, KMS_TAG_APP_PROC_NAME, KMS_TAG_EXPORT_PROC_NAME, KMS_TAG_DELETE_PROC_NAME };

/* import tag list */
static const enum kms_tags g_import_tag_black_list[] = { KMS_TAG_PARENT_KEY_ID, KMS_TAG_KDF_TYPE,
    KMS_TAG_BATCH_KEY_ID_IN_LIST, KMS_TAG_KDF_LABEL, KMS_TAG_KDF_CONTEXT, KMS_TAG_KEY_ID_RANDOM_SUFFIX };

/* create tag list */
static const enum kms_tags g_create_tag_black_list[] = { KMS_TAG_PARENT_KEY_ID, KMS_TAG_KDF_TYPE,
    KMS_TAG_BATCH_KEY_ID_IN_LIST, KMS_TAG_KDF_LABEL, KMS_TAG_KDF_CONTEXT, KMS_TAG_KEY_ID_RANDOM_SUFFIX };

/* kdf tag list */
static const enum kms_tags g_kdf_tag_black_list[] = { KMS_TAG_PARENT_KEY_ID };

/* single tag check */
static bool kms_single_tag_list_check(uint32_t kms_tag, struct kms_buffer_data *param_set)
{
    uint32_t i;
    uint32_t param_count = *(uint32_t *)(param_set->buffer);
    struct kms_param_t *params = (struct kms_param_t *)((uint8_t *)param_set->buffer + sizeof(param_count));
    for (i = 0; i < param_count; ++i) {
        if (kms_tag == params[i].tag)
            return true;
    }
    return false;
}

/* global tag white list check */
static bool kms_tag_white_list_check(struct kms_buffer_data *param_set)
{
    uint32_t i, j;
    uint32_t param_count = *(uint32_t *)(param_set->buffer);
    struct kms_param_t *params = (struct kms_param_t *)((uint8_t *)param_set->buffer + sizeof(param_count));
    for (i = 0; i < param_count; ++i) {
        uint32_t kms_tag = params[i].tag;
        bool check = false;
        for (j = 0; j < sizeof(g_tag_white_list) / sizeof(enum kms_tags); ++j) {
            if (kms_tag == g_tag_white_list[j]) {
                check = true;
                break;
            }
        }
        if (check == false) {
            tloge("tag white list check: invalid tag 0x%x\n", kms_tag);
            return false;
        }
    }
    return true;
}

/* black list check */
static bool kms_tag_black_list_check(struct kms_param_t *params, uint32_t param_count,
                                     const enum kms_tags tag_black_list[], uint32_t tag_count)
{
    uint32_t i, j;
    for (i = 0; i < param_count; ++i) {
        uint32_t kms_tag = params[i].tag;
        for (j = 0; j < tag_count; ++j)
            if (kms_tag == tag_black_list[j])
                return false;
    }
    return true;
}

static bool kms_tag_filter_in_list_check(struct kms_param_t *params, uint32_t param_count,
                                         const enum kms_tags tag_filter_in_list[], uint32_t tag_count)
{
    uint32_t i, j;
    uint32_t filter_in_count = 0;
    for (i = 0; i < param_count; ++i) {
        uint32_t kms_tag = params[i].tag;
        for (j = 0; j < tag_count; ++j)
            if (kms_tag == tag_filter_in_list[j]) {
                filter_in_count++;
                break;
            }
    }
    return (filter_in_count == param_count ? true : false);
}

static TEE_Result kms_tag_filter_in_list_implement(struct kms_buffer_data *param_set, struct kms_param_t *params,
    uint32_t param_count, const enum kms_tags tag_filter_in_list[], uint32_t tag_count)
{
    errno_t rc;
    uint32_t i, j;
    uint32_t filter_in_count = 0;
    uint32_t offset = sizeof(param_count);
    /* recorrect param_t */
    for (i = 0; i < param_count; ++i) {
        bool check = false;
        for (j = 0; j < tag_count; ++j)
            if (params[i].tag == tag_filter_in_list[j])
                check = true;
        if (check == true) {
            filter_in_count++;
            /* copy overlap check */
            if ((uintptr_t)((uint8_t *)param_set->buffer + offset) >= (uintptr_t)(&params[i])) {
                offset += sizeof(struct kms_param_t);
                continue;
            }
            rc = memcpy_s((uint8_t *)param_set->buffer + offset, param_set->length - offset,
                          &params[i], sizeof(struct kms_param_t));
            if (rc != EOK) {
                tloge("copy param set params failed!\n");
                return TEE_ERROR_SHORT_BUFFER;
            }
            offset += sizeof(struct kms_param_t);
        }
    }
    /* recorrect blob.offset */
    for (i = 0; i < filter_in_count; ++i) {
        enum kms_tag_type type = kms_tag_get_type(params[i].tag);
        if (type == KMS_BYTES)
            params[i].data.blob.data_offset -= (param_count - filter_in_count) * sizeof(struct kms_param_t);
    }
    /* copy buffer data */
    uint32_t buffer_offset = sizeof(param_count) + param_count * sizeof(struct kms_param_t);
    rc = memmove_s((uint8_t *)param_set->buffer + offset, param_set->length - offset,
                   (uint8_t *)param_set->buffer + buffer_offset, param_set->length - buffer_offset);
    if (rc != EOK) {
        tloge("copy param set buffer failed!\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    *(uint32_t *)param_set->buffer = filter_in_count;
    param_set->length -= (param_count - filter_in_count) * sizeof(struct kms_param_t);
    return TEE_SUCCESS;
}

TEE_Result kms_getmeta_params_check(struct kms_buffer_data *param_set)
{
    if (param_set == NULL || param_set->buffer == NULL || param_set->length < sizeof(uint32_t)) {
        tloge("getmeta params check: input param_set is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    enum kms_tags tag_white_list[] = { KMS_TAG_KEY_TYPE, KMS_TAG_KEY_SIZE };
    uint32_t i, j;
    uint32_t param_count = *(uint32_t *)(param_set->buffer);
    bool check = (param_count > MAX_TAG_NUMBER) ||
                 (param_count * sizeof(struct kms_param_t) > param_set->length - sizeof(param_count));
    if (check) {
        tloge("getmeta param length is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct kms_param_t *params = (struct kms_param_t *)((uint8_t *)param_set->buffer + sizeof(param_count));
    for (i = 0; i < param_count; ++i) {
        uint32_t kms_tag = params[i].tag;
        check = false;
        for (j = 0; j < sizeof(tag_white_list) / sizeof(enum kms_tags); ++j) {
            if (kms_tag == tag_white_list[j])
                check = true;
        }
        if (check == false)
            return KMS_ERROR_PARAM_CHECK_FAILED;
    }
    return TEE_SUCCESS;
}

TEE_Result kms_import_params_check(struct kms_buffer_data *param_set)
{
    bool check = (param_set == NULL || param_set->buffer == NULL || param_set->length < sizeof(uint32_t));
    if (check) {
        tloge("input import param_set is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    uint32_t param_count = *(uint32_t *)(param_set->buffer);
    check = (param_count > MAX_TAG_NUMBER) ||
                 (param_count * sizeof(struct kms_param_t) > param_set->length - sizeof(param_count));
    if (check) {
        tloge("import param length is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct kms_param_t *params = (struct kms_param_t *)((uint8_t *)param_set->buffer + sizeof(param_count));

    /* white list check */
    if (kms_tag_white_list_check(param_set) == false)
        return KMS_ERROR_PARAM_CHECK_FAILED;

    /* black list check, just ignore */
    if (kms_tag_black_list_check(params, param_count, g_import_tag_black_list,
                                 sizeof(g_import_tag_black_list) / sizeof(enum kms_tags)) == false)
        tloge("import params check: there exist illegal tag!\n");

    return TEE_SUCCESS;
}

TEE_Result kms_create_params_check(struct kms_buffer_data *param_set)
{
    bool check = (param_set == NULL || param_set->buffer == NULL || param_set->length < sizeof(uint32_t));
    if (check) {
        tloge("input create param_set is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    uint32_t param_count = *(uint32_t *)(param_set->buffer);
    check = (param_count > MAX_TAG_NUMBER) ||
                 (param_count * sizeof(struct kms_param_t) > param_set->length - sizeof(param_count));
    if (check) {
        tloge("create param length is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct kms_param_t *params = (struct kms_param_t *)((uint8_t *)param_set->buffer + sizeof(param_count));
    /* white list check */
    if (kms_tag_white_list_check(param_set) == false)
        return KMS_ERROR_PARAM_CHECK_FAILED;
    /* black list check, just ignore */
    if (kms_tag_black_list_check(params, param_count, g_create_tag_black_list,
                                 sizeof(g_create_tag_black_list) / sizeof(enum kms_tags)) == false)
        tloge("create param check: there exist illegal create tag!\n");

    return TEE_SUCCESS;
}

static bool kms_kdf_associated_tag_check(struct kms_buffer_data *param_set)
{
    if (kms_single_tag_list_check(KMS_TAG_KDF_TYPE, param_set) == false)
        return false;
    bool condition = (kms_single_tag_list_check(KMS_TAG_KDF_LABEL, param_set) &&
        kms_single_tag_list_check(KMS_TAG_KDF_CONTEXT, param_set));
    return condition;
}

TEE_Result kms_kdf_params_check(struct kms_buffer_data *param_set)
{
    bool check = (param_set == NULL || param_set->buffer == NULL || param_set->length < sizeof(uint32_t));
    if (check) {
        tloge("input kdf param_set is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    uint32_t param_count = *(uint32_t *)(param_set->buffer);
    check = (param_count > MAX_TAG_NUMBER) ||
                 (param_count * sizeof(struct kms_param_t) > param_set->length - sizeof(param_count));
    if (check) {
        tloge("kdf input param length is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct kms_param_t *params = (struct kms_param_t *)((uint8_t *)param_set->buffer + sizeof(param_count));
    /* white list check */
    if (kms_tag_white_list_check(param_set) == false)
        return KMS_ERROR_PARAM_CHECK_FAILED;

    /* black list check, just ignore */
    if (kms_tag_black_list_check(params, param_count, g_kdf_tag_black_list,
                                 sizeof(g_kdf_tag_black_list) / sizeof(enum kms_tags)) == false)
        tloge("kdf param check: there exist illegal tag!\n");

    /* kdf associated tag check */
    if (kms_kdf_associated_tag_check(param_set) == false) {
        tloge("kdf param check: associated tag check failed\n");
        return KMS_ERROR_PARAM_CHECK_FAILED;
    }

    return TEE_SUCCESS;
}

TEE_Result kms_persistent_tag_filter_in(struct kms_buffer_data *param_set)
{
    bool check = (param_set == NULL || param_set->buffer == NULL || param_set->length < sizeof(uint32_t));
    if (check) {
        tloge("input persistent param set is invalid\n");
        return TEE_ERROR_READ_DATA;
    }
    TEE_Result ret;
    uint32_t param_count = *(uint32_t *)(param_set->buffer);
    check = (param_count > MAX_TAG_NUMBER) ||
                 (param_count * sizeof(struct kms_param_t) > param_set->length - sizeof(param_count));
    if (check) {
        tloge("filter in input param length is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct kms_param_t *params = (struct kms_param_t *)((uint8_t *)param_set->buffer + sizeof(param_count));

    /* filter in check. If filter_in_count equals param_count, no need to copy */
    if (kms_tag_filter_in_list_check(params, param_count, g_persistent_tag_filter_in_list,
                                     sizeof(g_persistent_tag_filter_in_list) / sizeof(enum kms_tags)) == true)
        return TEE_SUCCESS;

    /* filter in implementation that includes recorrect params, blob.data_offset and buffer data */
    ret = kms_tag_filter_in_list_implement(param_set, params, param_count, g_persistent_tag_filter_in_list,
                                           sizeof(g_persistent_tag_filter_in_list) / sizeof(enum kms_tags));
    if (ret != TEE_SUCCESS) {
        tloge("implement kms persistent tag filter is failed!\n");
        return ret;
    }
    return TEE_SUCCESS;
}
