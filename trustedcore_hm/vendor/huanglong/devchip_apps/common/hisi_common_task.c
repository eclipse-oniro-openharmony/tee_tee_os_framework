/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: common TA
 */

#include "hi_tee_hal.h"
#include "hi_tee_errno.h"
#include "tee_common_utils.h"

#define TEEC_CMD_GET_VERSION 0

#define UNUSED(x) ((x) = (x))
#define PARA_NUM 4

/* define the parameter check macro */
#define CHECK_PARAM_TYPES(param_types, type0, type1, type2, type3) do { \
    if ((param_types) != TEE_PARAM_TYPES(type0, type1, type2, type3)) { \
        ta_debug("[%d]line bad parameter types!\n", __LINE__);          \
        return TEE_ERROR_BAD_PARAMETERS;                                \
    }                                                                   \
} while (0)

__DEFAULT TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;
    hi_char general_session_name[] = "tee_common_session";
    /* root id for all client */
    ret = AddCaller_CA_exec(general_session_name, 0);
    if (ret != TEE_SUCCESS) {
        tloge("AddCaller_CA_exec %s for root failed!\n", general_session_name);
        goto out;
    }

    ret = TEE_SUCCESS;
out:
    return ret;
}

__DEFAULT TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[PARA_NUM],
                                              hi_void **session_context)
{
    UNUSED(param_types);
    UNUSED(params);
    UNUSED(session_context);
    return TEE_SUCCESS;
}

__DEFAULT TEE_Result TA_InvokeCommandEntryPoint(hi_void *session_context, uint32_t cmd_id, uint32_t param_types,
    TEE_Param params[PARA_NUM])
{
    TEE_Result ret;
    UNUSED(session_context);

    switch (cmd_id) {
        case TEEC_CMD_GET_VERSION: {
            hi_void *buf = params[0].memref.buffer;
            hi_u32 buf_size = params[0].memref.size;
            hi_u32 total_size = params[1].value.a;

            common_check_pointer(buf);

            CHECK_PARAM_TYPES(param_types, TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_VALUE_INPUT,
                              TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

            ret = tee_common_get_version_info((hi_char *)buf, buf_size, total_size);
            if (ret != HI_SUCCESS) {
                ret = TEE_ERROR_GENERIC;
            } else {
                ret = TEE_SUCCESS;
            }
            break;
        }
        default: {
            ret = TEE_ERROR_BAD_PARAMETERS;
            tloge("Invalid cmd[0x%x]!\n", cmd_id);
            break;
        }
    }

    return  ret;
}

__DEFAULT void TA_CloseSessionEntryPoint(hi_void* session_context)
{
    UNUSED(session_context);
}

__DEFAULT void TA_DestroyEntryPoint(void)
{
    return;
}

