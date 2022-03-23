/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: public struct or define
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#ifndef KMS_KMS_TAG_API_H
#define KMS_KMS_TAG_API_H
#include "tee_internal_api.h"

TEE_Result tag_input_to_param_set(TEE_Param param, struct kms_buffer_data *param_set);
TEE_Result get_key_param(void *value, uint32_t kms_tag, const struct kms_buffer_data *param_set);
bool tag_exists_in_param_set(uint32_t kms_tag, const struct kms_buffer_data *param_set);
TEE_Result match_tag_in_param_set(uint32_t kms_tag, const void *expect_value, uint32_t value_len,
    const struct kms_buffer_data *param_set);
#endif
