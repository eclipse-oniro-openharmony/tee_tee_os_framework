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
#include <securec.h>
#include <tee_log.h>
#include <tee_ext_api.h>

TEE_Result TEE_EXT_create_cert_req(uint8_t *buf, size_t length, uint32_t key_type, uint8_t *file_name)
{
    (void)buf;
    (void)length;
    (void)key_type;
    (void)file_name;
    return TEE_ERROR_NOT_SUPPORTED;
}
TEE_Result TEE_EXT_verify_dev_cert(uint8_t *cert, uint32_t cert_len, uint8_t *parent_key, uint32_t parent_key_len)
{
    (void)cert;
    (void)cert_len;
    (void)parent_key;
    (void)parent_key_len;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_create_cert_req(uint8_t *buf, size_t length, uint32_t key_type, uint8_t *file_name)
{
    (void)buf;
    (void)length;
    (void)key_type;
    (void)file_name;
    return TEE_ERROR_NOT_SUPPORTED;
}
TEE_Result tee_verify_dev_cert(uint8_t *cert, uint32_t cert_len, uint8_t *parent_key, uint32_t parent_key_len)
{
    (void)cert;
    (void)cert_len;
    (void)parent_key;
    (void)parent_key_len;
    return TEE_ERROR_NOT_SUPPORTED;
}
