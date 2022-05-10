/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: gatekeeper auth token api implementation code
 * Create: 2022-04-12
 */
#include "tee_gk_auth_token.h"

TEE_Result tee_gatekeeper_get_verify_timestamp(uint32_t uid, uint64_t *timestamp)
{
    (void)uid;
    (void)timestamp;
    return TEE_ERROR_NOT_SUPPORTED;
}

