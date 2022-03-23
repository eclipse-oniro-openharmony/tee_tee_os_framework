/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Safety operator
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#include "kms_pub_def.h"
#include "tee_log.h"
#include "securec.h"

static uint32_t tag_appears_times_in_params(const struct kms_param_t *params, uint32_t param_count, uint32_t tag)
{
    uint32_t i;
    uint32_t find_times = 0;
    for (i = 0; i < param_count; i++) {
        if (tag == params[i].tag)
            find_times++;
    }
    return find_times;
}

static TEE_Result copy_tags_to_param_set(struct kms_param_set_t *param_set, uint32_t length, TEE_Param param)
{
    uint32_t offset = 0;
    uint32_t param_count = *(uint32_t *)param.memref.buffer;
    offset += sizeof(uint32_t);
    /* check param_count */
    bool check = (param_count > MAX_TAG_NUMBER ||
                  param_count * sizeof(struct kms_param_t) > (param.memref.size - offset));
    if (check) {
        tloge("copy tags: total param count is invalid %u\n", param_count);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    param_set->param_count = param_count;

    struct kms_param_t *params = (struct kms_param_t *)((uint8_t *)param_set + sizeof(uint32_t));
    struct kms_param_t *data = (struct kms_param_t *)((uint8_t *)param.memref.buffer + offset);

    /* copy tags and buffers from PARAM.memref.buffer into param_set */
    uint32_t data_len = param.memref.size - sizeof(uint32_t);
    if (data_len > 0) {
        errno_t rc = memcpy_s(params, length - sizeof(param_set->param_count),
                              data, data_len);
        if (rc != EOK) {
            tloge("copy tags and datas into param_set failed!\n");
            return TEE_ERROR_SHORT_BUFFER;
        }
        offset += data_len;
    }

    return TEE_SUCCESS;
}

/* param_set->buffer need to be freed in caller */
TEE_Result tag_input_to_param_set(TEE_Param param, struct kms_buffer_data *param_set)
{
    bool check = (param.memref.buffer == NULL || param.memref.size < sizeof(uint32_t));
    if (check) {
        tloge("param to set: input is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* check param_count */
    uint32_t param_count = *(uint32_t *)param.memref.buffer;
    uint32_t offset = sizeof(param_count);
    check = (param_count > MAX_TAG_NUMBER ||
             param_count * sizeof(struct kms_param_t) > (param.memref.size - offset));
    if (check) {
        tloge("param to set: total param count is invalid %u\n", param_count);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* check each param's buffer data length and judge total length */
    struct kms_param_t *params = (struct kms_param_t *)((uint8_t *)param.memref.buffer + offset);
    uint32_t i;
    for (i = 0; i < param_count; ++i) {
        enum kms_tag_type type = kms_tag_get_type(params[i].tag);
        if (type == KMS_BYTES || type == KMS_BYTES_REP) {
            if (params[i].data.blob.data_len > BUFFER_DATA_MAX_SIZE) {
                tloge("param to set: input buffer data is too large!\n");
                return TEE_ERROR_BAD_PARAMETERS;
            }
            offset += params[i].data.blob.data_len;
        }
        offset += sizeof(struct kms_param_t);
    }
    if (offset != param.memref.size) {
        tloge("param to set: input param length is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Now param.memref.size and format have been checked. */
    param_set->length = param.memref.size;
    param_set->buffer = (uint8_t *)TEE_Malloc(param_set->length, TEE_MALLOC_FILL_ZERO);
    if (param_set->buffer == NULL) {
        tloge("tag_input_to_param_set: malloc param_set_t fail\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_Result ret = copy_tags_to_param_set((struct kms_param_set_t *)param_set->buffer, param_set->length, param);
    if (ret != TEE_SUCCESS) {
        tloge("copy tags to param set error\n");
        return ret;
    }

    return TEE_SUCCESS;
}

/* IN: key TAG, OUT: value */
#define TAG_APEARS_ONCE 1
TEE_Result get_key_param(void *value, const uint32_t kms_tag, const struct kms_buffer_data *param_set)
{
    bool condition = (value == NULL || param_set == NULL || param_set->buffer == NULL);
    if (condition)
        return TEE_ERROR_BAD_PARAMETERS;

    uint32_t param_count = *(uint32_t *)param_set->buffer;
    struct kms_param_t *params = (struct kms_param_t *)((uint8_t *)param_set->buffer + sizeof(param_count));
    if (tag_appears_times_in_params(params, param_count, kms_tag) > TAG_APEARS_ONCE) {
        tloge("repeat tag 0x%x\n", kms_tag);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret = TEE_ERROR_ITEM_NOT_FOUND;
    for (uint32_t i = 0; i < param_count; ++i) {
        if (kms_tag != params[i].tag)
            continue;
        enum kms_tag_type type = kms_tag_get_type(kms_tag);
        switch (type) {
        case KMS_INTEGER: {
            *(uint32_t *)value = params[i].data.integer;
            ret = TEE_SUCCESS;
            break;
        }
        case KMS_BYTES: {
            struct kms_buffer_data *key_buffer = (struct kms_buffer_data *)value;
            key_buffer->length = params[i].data.blob.data_len;
            key_buffer->buffer = ((uint8_t *)param_set->buffer + params[i].data.blob.data_offset);
            ret = TEE_SUCCESS;
            break;
        }
        case KMS_BOOL:
            *(bool *)value = params[i].data.boolean;
            ret = TEE_SUCCESS;
            break;
        case KMS_INTEGER_REP:
        case KMS_DATE:
        default:
            tloge("unsupported kms tag type\n");
            break;
        }
    }
    return ret;
}

bool tag_exists_in_param_set(uint32_t kms_tag, const struct kms_buffer_data *param_set)
{
    bool condition = (param_set == NULL || param_set->buffer == NULL);
    if (condition) {
        tloge("tag exists: invaild param");
        return false;
    }

    uint32_t param_count = *(uint32_t *)param_set->buffer;
    struct kms_param_t *params = (struct kms_param_t *)((uint8_t *)param_set->buffer + sizeof(param_count));
    if (tag_appears_times_in_params(params, param_count, kms_tag) > 0)
        return true;
    return false;
}

/* Search for kms_tag whose value matches expect_value in param_set. */
TEE_Result match_tag_in_param_set(uint32_t kms_tag, const void *expect_value, uint32_t value_len,
    const struct kms_buffer_data *param_set)
{
    bool condition = (expect_value == NULL || value_len == 0 ||
        param_set == NULL || param_set->buffer == NULL);
    if (condition) {
        tloge("match tag: invaild param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    enum kms_tag_type type = kms_tag_get_type(kms_tag);
    bool repeatable = (type == KMS_BYTES_REP || type == KMS_INTEGER_REP);
    bool match_success = false;
    uint32_t param_count = *(uint32_t *)param_set->buffer;
    struct kms_param_t *params = (struct kms_param_t *)((uint8_t *)param_set->buffer + sizeof(param_count));
    for (uint32_t i = 0; i < param_count; ++i) {
        if (kms_tag != params[i].tag)
            continue;
        switch (type) {
        case KMS_INTEGER:
        case KMS_INTEGER_REP:
            match_success = ((value_len == sizeof(params[i].data.integer)) &&
                (*(uint32_t *)expect_value == params[i].data.integer));
            break;
        case KMS_BYTES:
        case KMS_BYTES_REP:
            match_success = ((value_len == params[i].data.blob.data_len) &&
                (TEE_MemCompare(((uint8_t *)param_set->buffer + params[i].data.blob.data_offset),
                (uint8_t *)expect_value, value_len) == TEE_SUCCESS));
            break;
        case KMS_BOOL:
            match_success = ((value_len == sizeof(params[i].data.boolean)) &&
                (*(bool *)expect_value == params[i].data.boolean));
            break;
        default:
            tloge("match tag: tag type unsupported\n");
            break;
        }
        condition = (match_success || (!repeatable));
        if (condition)
            break;
    }
    if (match_success)
        return TEE_SUCCESS;
    return TEE_ERROR_ITEM_NOT_FOUND;
}
