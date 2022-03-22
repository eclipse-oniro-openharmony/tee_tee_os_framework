/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: definition for kms kdf
 * Author: chengfuxing@huawei.com
 * Create: 2021-12-7
 */
#ifndef KMS_KDF_H
#define KMS_KDF_H
#include "tee_internal_api.h"
#include "kms_pub_def.h"
#define SHA256_BYTES 32
#define SHA384_BYTES 48
#define SHA512_BYTES 64
#define HMAC_SHA256_BYTES 32
#define MAX_SALT_BUFFER 4096
#define AES_BYTES 16
struct prf_len {
    enum kms_key_algorithm prf;
    uint32_t len;
};

TEE_Result audi_like_nist800_108_ctr_kdf(TEE_ObjectHandle key_obj, enum kms_key_algorithm prf,
    struct kms_buffer_data *label, struct kms_buffer_data *context, struct kms_buffer_data *target);
TEE_Result kdf_implement_algo(const struct kms_buffer_data *param_set, const TEE_ObjectHandle key_obj,
    struct kms_buffer_data *out_key);
#endif
