/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TA HDMIRX
 * Author: Hisilicon multimedia interface software group
 * Create: 2020/02/05
 */

#include "hi_tee_hal.h"
#include "tee_drv_hdmirx_ioctl.h"
#include "tee_api_hdmirx.h"

#define TEEC_CMD_HDMIRX_CHK_MCU_CODE 0
#define TEEC_CMD_HDMIRX_GET_MAP      1
#define TEEC_CMD_HDMIRX_CHK_DS_READY 2

#define unused(x) ((x) = (x))

__DEFAULT TEE_Result TA_CreateEntryPoint(void)
{
    return AddCaller_CA_exec((char *)"default", 0);
}

__DEFAULT TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
    TEE_Param params[4], void **session_context) /* 4, param num */
{
    (void)param_types;
    (void)params;
    (void)session_context;

    return TEE_SUCCESS;
}

static hi_bool hdmirx_check_param_type(hi_u32 cmd, hi_u32 param_types)
{
    hi_u32 tmp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    switch (cmd) {
        case TEEC_CMD_HDMIRX_CHK_MCU_CODE:
            tmp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);
            break;
        case TEEC_CMD_HDMIRX_GET_MAP:
            tmp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);
            break;
        case TEEC_CMD_HDMIRX_CHK_DS_READY:
            tmp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);
            break;
        default:
            break;
    }

    if (tmp != param_types) {
        tloge("TA command not valid\n");
        return HI_FALSE;
    }

    return HI_TRUE;
}

__DEFAULT TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t command_id,
                                                uint32_t param_types, TEE_Param params[4]) /* 4, param num */
{
    TEE_Result ret = HI_FAILURE;
    tee_hdmirx_ioctl_rpt_map rpt_map = {0};
    tee_hdmirx_ioctl_ds_ready ds = {0};

    unused(session_context);
    if (hdmirx_check_param_type(command_id, param_types) != HI_TRUE) {
        tloge("check param fail\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    switch (command_id) {
        case TEEC_CMD_HDMIRX_CHK_MCU_CODE:
            ret = tee_api_hdmirx_ioctl(HDMIRX_IOCTL_CHK_MCU_CODE, &params[0].value.a);
            break;
        case TEEC_CMD_HDMIRX_GET_MAP:
            rpt_map.port = params[0].value.a;
            ret = tee_api_hdmirx_ioctl(HDMIRX_IOCTL_GET_MAP, &rpt_map);
            if (memcpy_s(params[1].memref.buffer, params[1].memref.size, &rpt_map.map, sizeof(rpt_map.map)) != EOK) {
                tloge("memcpy_s error\n");
                ret = TEE_ERROR_GENERIC;
            }
            break;
        case TEEC_CMD_HDMIRX_CHK_DS_READY:
            ds.port = params[0].value.a;
            ret = tee_api_hdmirx_ioctl(HDMIRX_IOCTL_CHK_DS_READY, &ds);
            if (memcpy_s(params[1].memref.buffer, params[1].memref.size,
                &ds.downstream, sizeof(ds.downstream)) != EOK) {
                tloge("memcpy_s error\n");
                ret = TEE_ERROR_GENERIC;
            }
            break;
        default:
            ret = TEE_ERROR_INVALID_CMD;
            break;
    }

    if (ret != TEE_SUCCESS) {
        tloge("HDMIRX TA invoke command[0x%x] failed, ret[0x%x]\n", command_id, ret);
    }

    return ret;
}

__DEFAULT void TA_CloseSessionEntryPoint(void *session_context)
{
    (void)(session_context);
}

__DEFAULT void TA_DestroyEntryPoint(void)
{
}
