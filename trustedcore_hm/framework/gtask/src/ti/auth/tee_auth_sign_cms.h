/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: Header file for timer_hw
 * Author: zhoulele zhoulele@huawei.com
 * Create: 2022-04-23
 */

#ifndef GTASK_TEE_AUTH_SIGN_CMS_H
#define GTASK_TEE_AUTH_SIGN_CMS_H

#include "tee_defines.h"

TEE_Result signature_verify_cms(const uint8_t *sig_buf, uint32_t sig_len, const uint8_t *hash_buf, size_t hash_len);
#endif
