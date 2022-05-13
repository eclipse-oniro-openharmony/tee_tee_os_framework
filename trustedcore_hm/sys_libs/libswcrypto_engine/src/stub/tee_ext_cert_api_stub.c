/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: extension certification api
 * Create: 2022-03-30
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
