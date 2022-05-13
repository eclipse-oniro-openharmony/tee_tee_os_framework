/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: crypto extral api stub implementation
 * Create: 2022-04-21
 */
#include "crypto_ext_api.h"

TEE_Result tee_ext_kdf_func(struct kdf_params_t *params, uint32_t hash_mode, uint32_t kdf_mode)
{
    (void)hash_mode;
    (void)kdf_mode;
    (void)params;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result engine_power_on(void)
{
    return TEE_SUCCESS;
}

TEE_Result engine_power_off(void)
{
    return TEE_SUCCESS;
}

bool eps_support_cdrm_enhance(void)
{
    return false;
}

TEE_Result do_eps_ctrl(uint32_t type, uint32_t profile)
{
    (void)type;
    (void)profile;
    return TEE_ERROR_NOT_SUPPORTED;
}
