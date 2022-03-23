/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: verify cms signature in ct.
 * Author: hemuyang1@huawei.com
 * Create: 2021-06-10
 */
#ifndef GTASK_CMS_SIGNATURE_VERIFY_H
#define GTASK_CMS_SIGNATURE_VERIFY_H

#include "tee_defines.h"

struct cms_sign_info {
    uint8_t *sig_buf;
    uint32_t sig_len;
    uint8_t *cms_header;
    uint8_t *cms_buf;
    uint32_t cms_len;
    uint8_t *ini_header;
    uint8_t *ini_buf;
    uint32_t ini_len;
    uint8_t *crl_header;
    uint8_t *crl_buf;
    uint32_t crl_len;
};

#define DEVICE_CRL_MAX 0x4000 /* 16KB */

TEE_Result check_cms_signature(const struct cms_sign_info *sign_info);
TEE_Result cms_crl_update(uint8_t *crl, uint32_t crl_len);
#endif
