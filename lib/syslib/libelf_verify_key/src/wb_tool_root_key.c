/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: tee load key code
 * Create: 2020.03.04
 */
#include "ta_load_key.h"

#include <tee_defines.h>
#include <tee_log.h>
#include <securec.h>
#ifdef CONFIG_GENERIC_LOAD_KEY
#include "wb_tool_128_root_key.h"
#endif

TEE_Result get_wb_tool_key(struct wb_tool_key *tool_key)
{
    if (tool_key == NULL) {
        tloge("check tool key params error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tloge("error wb tool version: %d\n", tool_key->tool_ver);
    return TEE_ERROR_BAD_PARAMETERS;
}
