/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: public struct or define
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#ifndef KMS_GP_KEYBLOB_OPERATION_H
#define KMS_GP_KEYBLOB_OPERATION_H
#include <string.h>
#include "kms_pub_def.h"

TEE_Result key_blob_mac(struct kms_buffer_data *derived_factor, struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data);
TEE_Result gp_keyblob_to_key(const struct kms_buffer_data *key_blob, struct kms_buffer_data *derived_factor,
    TEE_ObjectHandle *key_obj);
TEE_Result gp_key_to_buffer(const TEE_ObjectHandle key_obj, struct gp_key_base_info *bi,
    struct kms_buffer_data *key_blob);
TEE_Result mac_generate(struct gp_key_opera_input *koi);
TEE_Result crypto_kms_keyblob(struct kms_buffer_data *key_blob, const struct kms_buffer_data *derived_factor,
    uint32_t tee_mode);
#endif
