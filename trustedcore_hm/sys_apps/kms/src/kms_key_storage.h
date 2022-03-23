/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:kms key storage functions
 * Create: 2021-12-01
 */

#ifndef KMS_KMS_KEY_STORAGE_H
#define KMS_KMS_KEY_STORAGE_H

#include "kms_pub_def.h"

TEE_Result kms_store_key(const struct kms_buffer_data *key_id, const struct kms_buffer_data *key_blob,
    const struct kms_buffer_data *param_set);

TEE_Result kms_access_key(const struct kms_buffer_data *key_id);

TEE_Result kms_get_key(const struct kms_buffer_data *id_or_blob, struct kms_buffer_data *key_blob);

void kms_release_key(const struct kms_buffer_data *id_or_blob, struct kms_buffer_data *key_blob);

TEE_Result kms_delete_key(const struct kms_buffer_data *id_or_blob);
#endif
