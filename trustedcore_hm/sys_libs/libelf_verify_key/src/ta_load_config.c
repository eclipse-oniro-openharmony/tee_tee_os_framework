/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: ta load config
 * Create: 2022-1-19
 */
#include "ta_load_config.h"
#include <stdbool.h>

#ifdef TEE_DISABLE_TA_SIGN_VERIFY
static const bool g_tee_disable_ta_signature = true;
#else
static const bool g_tee_disable_ta_signature = false;
#endif

bool get_ta_signature_ctrl(void)
{
    return g_tee_disable_ta_signature;
}
