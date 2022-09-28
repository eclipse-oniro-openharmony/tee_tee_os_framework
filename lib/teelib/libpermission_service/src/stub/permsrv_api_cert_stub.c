/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: permission service implementation stub
 * Create: 2022-04-01
 */
#include "permsrv_api_cert.h"

TEE_Result ta_signing_cert_import(const char *cert_buf, uint32_t cert_size, const char *pub_key_buf, uint32_t pub_size)
{
    (void)cert_buf;
    (void)cert_size;
    (void)pub_key_buf;
    (void)pub_size;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result ta_signing_cert_export(uint8_t *dst, uint32_t *len, uint32_t limit)
{
    (void)dst;
    (void)len;
    (void)limit;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result ta_signing_cert_destroy(void)
{
    return TEE_ERROR_NOT_SUPPORTED;
}
