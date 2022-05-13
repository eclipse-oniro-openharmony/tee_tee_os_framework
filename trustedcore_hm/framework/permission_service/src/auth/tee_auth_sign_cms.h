/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cms signature auth
 * Author: wangchunxu1@huawei.com
 * Create: 2020.06.18
 */

#ifndef GTASK_TEE_AUTH_SIGN_CMS_H
#define GTASK_TEE_AUTH_SIGN_CMS_H

#include "tee_defines.h"

TEE_Result verify_cms_signature(const uint8_t *hash_buf, size_t hash_len, const uint8_t *sig_buf, uint32_t sig_len);
#endif
