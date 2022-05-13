/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: soft engine stub of boringssl
 * Create: 2022-03-30
 */
#include <securec.h>
#include <tee_log.h>
#include "crypto_wrapper.h"

TEE_Result aes_key_wrap(struct cdrm_params *params)
{
    (void)params;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result aes_key_unwrap(struct cdrm_params *params)
{
    (void)params;
    return TEE_ERROR_NOT_SUPPORTED;
}
