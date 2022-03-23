/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: implament GP API using boringssl
 * Create: 2019-11-21
 */
#include "tee_chinadrm_gmssl_api.h"
#include <tee_crypto_api.h>
#include <tee_log.h>
#include <ccmgr_ops.h>
#ifdef DX_ENABLE
#include <cdrmr_cipher.h>
#endif

#define POWER_ON     1
#define POWER_OFF    2
#define HIGH_PROFILE 0

#ifdef DX_ENABLE
static int32_t set_eps(void)
{
    if (!TEE_SupportCdrmEnhance()) {
        tloge("eps is not supported");
        return TEE_ERROR_NOT_SUPPORTED;
    }
    TEE_Result ret = TEE_EPS_Ctrl(POWER_ON, HIGH_PROFILE);
    if (ret != TEE_SUCCESS) {
        tloge("eps power on failed");
        return ret;
    }
    return TEE_SUCCESS;
}
#endif

int32_t cdrm_eps_sm2_sign(void *priv_key, uint8_t *input, uint32_t input_len, void *signature)
{
    bool check = (priv_key == NULL || input == NULL || input_len == 0 || signature == NULL);
    if (check) {
        tloge("invalid params");
        return TEE_ERROR_BAD_PARAMETERS;
    }
#ifdef DX_ENABLE
    int32_t ret = set_eps();
    if (ret != TEE_SUCCESS)
        return ret;

    ret = __cc_eps_sm2_sign(priv_key, input, input_len, signature);
    (void)TEE_EPS_Ctrl(POWER_OFF, HIGH_PROFILE);
    return ret;
#else
    return TEE_ERROR_NOT_SUPPORTED;
#endif
}

int32_t cdrm_eps_sm2_verify(void *public_key, uint8_t *input, uint32_t input_len, void *signature)
{
    bool check = (public_key == NULL || input == NULL || input_len == 0 || signature == NULL);
    if (check) {
        tloge("invalid params");
        return TEE_ERROR_BAD_PARAMETERS;
    }
#ifdef DX_ENABLE
    int32_t ret = set_eps();
    if (ret != TEE_SUCCESS)
        return ret;

    ret = __cc_eps_sm2_verify(public_key, input, input_len, signature);
    (void)TEE_EPS_Ctrl(POWER_OFF, HIGH_PROFILE);
    return ret;
#else
    return TEE_ERROR_NOT_SUPPORTED;
#endif
}

int32_t cdrm_eps_sm2_encrypt(void *public_key, uint8_t *input, uint32_t input_len, void *cipher, uint32_t clen)
{
    bool check = (public_key == NULL || input == NULL || input_len == 0 || cipher == NULL);
    if (check) {
        tloge("invalid params");
        return TEE_ERROR_BAD_PARAMETERS;
    }
#ifdef DX_ENABLE
    int32_t ret = set_eps();
    if (ret != TEE_SUCCESS)
        return ret;

    ret = __cc_eps_sm2_encrypt(public_key, input, input_len, cipher, clen);
    (void)TEE_EPS_Ctrl(POWER_OFF, HIGH_PROFILE);
    return ret;
#else
    (void)clen;
    return TEE_ERROR_NOT_SUPPORTED;
#endif
}
int32_t cdrm_eps_sm2_decrypt(void *priv_key, uint8_t *output, uint32_t *output_len, void *cipher, uint32_t clen)
{
    bool check = (priv_key == NULL || output == NULL || output_len == NULL || *output_len == 0 || cipher == NULL);
    if (check) {
        tloge("invalid params");
        return TEE_ERROR_BAD_PARAMETERS;
    }
#ifdef DX_ENABLE
    int32_t ret = set_eps();
    if (ret != TEE_SUCCESS)
        return ret;

    ret = __cc_eps_sm2_decrypt(priv_key, output, output_len, cipher, clen);
    (void)TEE_EPS_Ctrl(POWER_OFF, HIGH_PROFILE);
    return ret;
#else
    (void)clen;
    return TEE_ERROR_NOT_SUPPORTED;
#endif
}

#ifdef DX_ENABLE
static void cdrm_eps_params_transfor(struct cdrm_trans_params *dst_data, const struct cdrm_params *src_data)
{
    dst_data->pkey = (uintptr_t)src_data->pkey;
    dst_data->pkey_len = src_data->pkey_len;
    dst_data->iv = (uintptr_t)src_data->iv;
    dst_data->iv_len = src_data->iv_len;
    dst_data->input_buffer = (uintptr_t)src_data->input_buffer;
    dst_data->input_len = src_data->input_len;
    dst_data->output_buffer = (uintptr_t)src_data->output_buffer;
    dst_data->output_len = (uintptr_t)src_data->output_len;
    dst_data->context = (uintptr_t)src_data->context;
    dst_data->alg = src_data->alg;
}
#endif

int32_t cdrm_eps_sm4_crypto(uint32_t algorithm, uint32_t mode, struct cdrm_params *params)
{
    struct cdrm_trans_params data = { 0 };

    bool check = (params == NULL || params->pkey == NULL || params->pkey_len == 0 || params->input_buffer == NULL ||
                  params->input_len == 0 || params->output_buffer == NULL || params->output_len == NULL ||
                  (mode != TEE_MODE_ENCRYPT && mode != TEE_MODE_DECRYPT));
    if (check) {
        tloge("params Invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
#ifdef DX_ENABLE
    int32_t ret = set_eps();
    if (ret != TEE_SUCCESS)
        return ret;

    if (mode == TEE_MODE_ENCRYPT) {
        cdrm_eps_params_transfor(&data, params);
        ret = __cc_eps_sm4_symmetric_encrypt(algorithm, &data);
    } else {
        cdrm_eps_params_transfor(&data, params);
        ret = __cc_eps_sm4_symmetric_decrypt(algorithm, &data);
    }
    (void)TEE_EPS_Ctrl(POWER_OFF, HIGH_PROFILE);
    return ret;
#else
    (void)algorithm;
    (void)data;
    return TEE_ERROR_NOT_SUPPORTED;
#endif
}

TEE_Result cdrm_eps_sm4_config(void **context, uint32_t *context_len, struct cdrm_params *params)
{
    struct cdrm_trans_params data = { 0 };

    bool check = (context == NULL || context_len == NULL || params == NULL || params->pkey == NULL ||
        params->pkey_len == 0 || params->iv == NULL || params->iv_len == 0);
    if (check) {
        tloge("params Invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
#ifdef DX_ENABLE
    int32_t ret = set_eps();
    if (ret != TEE_SUCCESS)
        return (TEE_Result)ret;

    struct cdrmr_cipher_user_ctx *puser_ctx = TEE_Malloc(sizeof(*puser_ctx), 0);
    if (puser_ctx == NULL) {
        tloge("malloc sm4 context failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    cdrm_eps_params_transfor(&data, params);
    ret = __cc_eps_sm4_config(puser_ctx, &data);
    if (ret != TEE_SUCCESS) {
        tloge("sm4 config failed");
        TEE_Free(puser_ctx);
        return ret;
    }
    *context = puser_ctx;
    *context_len = sizeof(*puser_ctx);
    return TEE_SUCCESS;
#else
    (void)data;
    return TEE_ERROR_NOT_SUPPORTED;
#endif
}

TEE_Result cdrm_eps_sm4_cenc_decrypt(void *context, uint8_t *input, uint32_t input_len,
    uint8_t *output, uint32_t *output_len)
{
    struct cdrm_trans_params data = { 0 };

    bool check = (context == NULL || input == NULL || output == NULL || input_len == 0 || output_len == NULL ||
        *output_len < input_len);
    if (check) {
        tloge("invalid params");
        return TEE_ERROR_BAD_PARAMETERS;
    }
#ifdef DX_ENABLE
    struct cdrm_params params = { 0 };
    params.input_buffer       = input;
    params.input_len          = input_len;
    params.output_buffer      = output;
    params.output_len         = output_len;

    cdrm_eps_params_transfor(&data, &params);
    TEE_Result ret = (TEE_Result)__cc_eps_sm4_cenc_decrypt(context, &data);
    return ret;
#else
    (void)data;
    return TEE_ERROR_NOT_SUPPORTED;
#endif
}
