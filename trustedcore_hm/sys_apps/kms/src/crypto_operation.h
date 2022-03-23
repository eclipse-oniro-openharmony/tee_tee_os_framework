/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: public struct or define
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#ifndef KMS_CRYPTO_OPERATION_H
#define KMS_CRYPTO_OPERATION_H

#include "kms_pub_def.h"
#include "kms_key_node.h"

#define KEY_NODE_RESERVE_NUMBER 10
#define KMS_KEY_VERSION_1 20200506
#define KMS_KEY_VERSION_2 2
#define KMS_BLOB_MAC_MODE_CHECK 1
#define KMS_BLOB_MAC_MODE_GENERATE 2
#define KMS_BYTE_TO_BITS 8

TEE_Result kms_create_key(const struct kms_buffer_data *param_set, struct kms_buffer_data *key_blob);
TEE_Result kms_crypto(struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data);
TEE_Result kms_digest(const struct kms_buffer_data *param_set, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data);
TEE_Result kms_sign_verify(struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data);
TEE_Result kms_mac_generate(struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, const struct kms_buffer_data *in_data, struct kms_buffer_data *out_data);
TEE_Result kms_begin(struct kms_buffer_data *key_blob, const struct kms_buffer_data *param_set,
    uint32_t kms_mod, struct kms_buffer_data *opt_handle);
TEE_Result kms_update(const struct kms_buffer_data *opt_handle, uint32_t kms_mod, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data);
TEE_Result kms_finish(const struct kms_buffer_data *opt_handle, uint32_t kms_mod, const struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data);
TEE_Result kms_import_key(const struct kms_buffer_data *param_set, const struct kms_buffer_data *in_key,
    struct kms_buffer_data *key_buffer);
TEE_Result kms_export_key(const struct kms_buffer_data *param_set, struct kms_buffer_data *out_key,
    struct kms_buffer_data *key_blob);
TEE_Result kms_kdf(const struct kms_buffer_data *param_set, const struct kms_buffer_data *target_key,
    struct kms_buffer_data *key_blob, struct kms_buffer_data *kdf_key_blob);
TEE_Result kms_getmeta(const struct kms_buffer_data *in_key, const struct kms_buffer_data *in_param_set,
    struct kms_buffer_data *out_param_set);
TEE_Result kms_delete(const struct kms_buffer_data *param_set, struct kms_buffer_data *key_blob);
TEE_Result kms_abort(const struct kms_buffer_data *opt_handle);
#endif
