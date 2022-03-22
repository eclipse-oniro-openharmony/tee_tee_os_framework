/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: definition for kms params check
 * Create: 2021-12-14
 */
#ifndef KMS_PARAMS_CHECK_H
#define KMS_PARAMS_CHECK_H
#include "kms_pub_def.h"

/* param check functions */
TEE_Result kms_kdf_params_check(struct kms_buffer_data *param_set);
TEE_Result kms_create_params_check(struct kms_buffer_data *param_set);
TEE_Result kms_import_params_check(struct kms_buffer_data *param_set);
TEE_Result kms_getmeta_params_check(struct kms_buffer_data *param_set);

/* param filter function */
TEE_Result kms_persistent_tag_filter_in(struct kms_buffer_data *param_set);

#endif
