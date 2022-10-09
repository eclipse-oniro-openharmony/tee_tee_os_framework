/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: permsrv cert api interface head file
 * Create: 2022-04-01
 */

#ifndef __PERSRV_API_CERT_H__
#define __PERSRV_API_CERT_H__

#include "tee_defines.h"

TEE_Result ta_signing_cert_import(const char *cert_buf, uint32_t cert_size, const char *pub_key_buf, uint32_t pub_size);
TEE_Result ta_signing_cert_export(uint8_t *dst, uint32_t *len, uint32_t limit);
TEE_Result ta_signing_cert_destroy(void);
#endif
