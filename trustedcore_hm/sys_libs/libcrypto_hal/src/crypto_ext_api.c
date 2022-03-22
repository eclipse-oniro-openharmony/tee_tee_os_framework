/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: crypto extral api implementation
 * Create: 2020-02-21
 */
#include "crypto_ext_api.h"
#include <tee_log.h>
#include <ccmgr_ops_ext.h> /* __CC_CRYS_KDF_KeyDerivFunc */
#include <ccmgr_ops.h>

TEE_Result tee_ext_kdf_func(struct kdf_params_t *params, uint32_t hash_mode, uint32_t kdf_mode)
{
    bool check = (params == NULL || params->key == NULL || params->key_size == 0 || params->out == NULL ||
        params->out_size == 0);
    if (check) {
        tloge("invalid parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret;

#ifdef DX_ENABLE
    ret = (TEE_Result)__CC_CRYS_KDF_KeyDerivFunc(params->key, params->key_size, NULL, (CRYS_KDF_HASH_OpMode_t)hash_mode,
        (CRYS_KDF_DerivFuncMode_t)kdf_mode, params->out, params->out_size);
#else
    ret = TEE_ERROR_NOT_SUPPORTED;
    (void)hash_mode;
    (void)kdf_mode;
#endif
    return ret;
}

TEE_Result engine_power_on(void)
{
    TEE_Result ret;

#ifdef DX_ENABLE
    ret = (TEE_Result)__CC_DX_power_on();
#else
    ret = TEE_SUCCESS;
#endif
    return ret;
}

TEE_Result engine_power_off(void)
{
    TEE_Result ret;

#ifdef DX_ENABLE
    ret = (TEE_Result)__CC_DX_power_down();
#else
    ret = TEE_SUCCESS;
#endif
    return ret;
}

bool eps_support_cdrm_enhance(void)
{
#ifdef DX_ENABLE
    return __CC_EPS_SupportCdrmEnhance();
#else
    return false;
#endif
}
TEE_Result do_eps_ctrl(uint32_t type, uint32_t profile)
{
#ifdef DX_ENABLE
    CRYSError_t ret;
    ret = __CC_EPS_CTRL(type, profile);
    return ret;
#else
    (void)type;
    (void)profile;
    return TEE_ERROR_NOT_SUPPORTED;
#endif
}
