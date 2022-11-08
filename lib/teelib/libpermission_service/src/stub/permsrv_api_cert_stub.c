/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
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
