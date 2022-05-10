/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: chinadrm gmssl stub func
 * Create: 2022-04-21
 */
#include "tee_chinadrm_gmssl_api.h"
#include <tee_crypto_api.h>
#include <tee_log.h>
#include <ccmgr_ops.h>

#define POWER_ON     1
#define POWER_OFF    2
#define HIGH_PROFILE 0

int32_t cdrm_eps_sm2_sign(void *priv_key, uint8_t *input, uint32_t input_len, void *signature)
{
    (void)priv_key;
    (void)input;
    (void)input_len;
    (void)signature;
    return TEE_ERROR_NOT_SUPPORTED;
}

int32_t cdrm_eps_sm2_verify(void *public_key, uint8_t *input, uint32_t input_len, void *signature)
{
    (void)public_key;
    (void)input;
    (void)input_len;
    (void)signature;
    return TEE_ERROR_NOT_SUPPORTED;
}

int32_t cdrm_eps_sm2_encrypt(void *public_key, uint8_t *input, uint32_t input_len, void *cipher, uint32_t clen)
{
    (void)public_key;
    (void)input;
    (void)input_len;
    (void)cipher;
    (void)clen;
    return TEE_ERROR_NOT_SUPPORTED;
}

int32_t cdrm_eps_sm2_decrypt(void *priv_key, uint8_t *output, uint32_t *output_len, void *cipher, uint32_t clen)
{
    (void)priv_key;
    (void)output;
    (void)output_len;
    (void)cipher;
    (void)clen;
    return TEE_ERROR_NOT_SUPPORTED;
}

int32_t cdrm_eps_sm4_crypto(uint32_t algorithm, uint32_t mode, struct cdrm_params *params)
{
    (void)algorithm;
    (void)mode;
    (void)params;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result cdrm_eps_sm4_config(void **context, uint32_t *context_len, struct cdrm_params *params)
{
    (void)context;
    (void)context_len;
    (void)params;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result cdrm_eps_sm4_cenc_decrypt(void *context, uint8_t *input, uint32_t input_len,
    uint8_t *output, uint32_t *output_len)
{
    (void)context;
    (void)input;
    (void)input_len;
    (void)output;
    (void)output_len;
    return TEE_ERROR_NOT_SUPPORTED;
}
