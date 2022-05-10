/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: verify cms signature in ct.
 * Author: hemuyang1@huawei.com
 * Create: 2021-06-10
 */
#ifndef GTASK_TA_CMS_SIGNATURE_VERIFY_H
#define GTASK_TA_CMS_SIGNATURE_VERIFY_H

#include "tee_defines.h"
#include "cms_signature_verify.h"

#define CMS_SIGNATURE_TAG     0xCA0A0A01
#define CMS_SIGNATURE_CRL_TAG 0xCA0A0A02
#define CMS_SIGNATURE_CMS_TAG 0xCA0A0A03

TEE_Result ta_cms_signature_verify(uint8_t *signature, uint32_t signature_size, uint8_t *hash, uint32_t hash_size);
#endif
