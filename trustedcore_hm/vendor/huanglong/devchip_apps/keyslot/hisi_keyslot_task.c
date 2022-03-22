/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: klad TA
 * Author: linux SDK team
 * Create: 2019-07-23
 */

#include "hi_tee_hal.h"
#include "hi_tee_log.h"
#include "hi_tee_keyslot.h"
#include "hi_tee_module_id.h"

#define unused(x) ((x) = (x))

#define KEYSLOT_CMD_CREATE         0
#define KEYSLOT_CMD_DESTORY        1
#define KEYSLOT_CMD_LOG_LEVEL      0xff

__DEFAULT TEE_Result TA_CreateEntryPoint(hi_void)
{
    AddCaller_CA_exec("default", 0);
    return TEE_SUCCESS;
}

__DEFAULT TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[0x4], hi_void **session_context)
{
    unused(param_types);
    unused(params);
    unused(session_context);
    return TEE_SUCCESS;
}

__DEFAULT TEE_Result TA_InvokeCommandEntryPoint(hi_void *session_context, uint32_t cmd_id,
                                                uint32_t param_types, TEE_Param params[0x4])
{
    TEE_Result ret = TEE_SUCCESS;
    hi_handle handle = 0;
    unused(session_context);

    switch (cmd_id) {
        case KEYSLOT_CMD_CREATE: {
            hi_tee_keyslot_type type = (hi_tee_keyslot_type)params[0].value.a;
            if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)) {
                ret = TEE_ERROR_BAD_PARAMETERS;
                break;
            }
            ret = hi_tee_keyslot_create(type, &handle);
            params[0].value.b = handle;
            break;
        }
        case KEYSLOT_CMD_DESTORY: {
            if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)) {
                ret = TEE_ERROR_BAD_PARAMETERS;
                break;
            }
            handle = params[0].value.a;
            ret = hi_tee_keyslot_destroy(handle);
            break;
        }
        case KEYSLOT_CMD_LOG_LEVEL: {
            tloge("set keyslot log level[0x%x]\n", params[0].value.a);
            ret =  hi_tee_log_set_level(HI_ID_KEYSLOT, params[0].value.a);
            break;
        }
        default: {
            ret = TEE_ERROR_BAD_PARAMETERS;
            break;
        }
    }
    if (ret == TEE_SUCCESS) {
        tloge("Invoke command[0x%x] suc\n", cmd_id);
    } else {
        tloge("Invoke command[0x%x] failed, ret[0x%x]\n", cmd_id, ret);
    }
    return  ret;
}

__DEFAULT hi_void TA_CloseSessionEntryPoint(hi_void *session_context)
{
    unused(session_context);
}

__DEFAULT hi_void TA_DestroyEntryPoint(hi_void)
{
    return;
}
