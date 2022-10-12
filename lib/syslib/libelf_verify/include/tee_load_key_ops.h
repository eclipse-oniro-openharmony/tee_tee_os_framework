/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:  Tee-load-extension-manifest function declaration.
 * Author: yuanhao34@huawei.com
 * Create: 2021-7-7
 */
#ifndef GTASK_TEE_LOAD_KEYOPS_H
#define GTASK_TEE_LOAD_KEYOPS_H

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "tee_defines.h"
#include "ta_load_key.h"

RSA *get_private_key(int32_t img_version, enum ta_type type);
void free_private_key(RSA *priv_key);

TEE_Result tee_secure_ta_release_verify(const uint8_t *hash, uint32_t hash_size, const uint8_t *signature,
                                         uint32_t signature_size);
TEE_Result tee_secure_img_hash_ops(const uint8_t *hash_context, size_t context_size, uint8_t *hash_result,
                                   size_t hash_result_size);
#endif
