/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TA hdmitx
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-01-18
 */

#include "hi_tee_hal.h"
#include "hi_type_dev.h"
#include "tee_drv_ioctl_hdmitx.h"
#include "tee_api_hdmitx.h"

#define unused(x) ((x) = (x))

__DEFAULT TEE_Result TA_CreateEntryPoint(hi_void)
{
    return AddCaller_CA_exec((hi_char *)"task_hisi_hdmitx", 0);
}

__DEFAULT TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4], /* 4, param num */
    hi_void **sessionContext)
{
    unused(paramTypes);
    unused(params);
    unused(sessionContext);
    return TEE_SUCCESS;
}

__DEFAULT TEE_Result TA_InvokeCommandEntryPoint(hi_void *sessionContext, uint32_t commandID,
                                                uint32_t paramTypes, TEE_Param params[4]) /* 4, param num */
{
    hi_s32 ret;
    hi_u32 param_type;
    hi_u32 *buf_ptr = HI_NULL;
    struct tee_hdmitx_ioctl tee_ioctl;

    unused(sessionContext);
    if (params == HI_NULL) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = HI_FAILURE;
    param_type =  TEE_PARAM_TYPE_GET(paramTypes, 1);
    if (param_type == TEE_PARAM_TYPE_MEMREF_INPUT && params[1].memref.buffer && /* param 1 */
        params[1].memref.size >= sizeof(hi_u32) * 2) {  /* param 1; 2 hi_u32 size */
        buf_ptr = (hi_u32 *)params[1].memref.buffer; /* param 1 */
        tee_ioctl.hdmi_id = buf_ptr[0];  /* byte 0  */
        tee_ioctl.cmd_id = buf_ptr[1]; /* byte 1 */
        tee_ioctl.data = (hi_void *)(buf_ptr + 2); /* byte 2 */
        tee_ioctl.data_size = params[1].memref.size - sizeof(hi_u32) * 2; /* param 1 ; 2 hi_u32 size  */
        ret = tee_api_hdmitx_ioctl(HDMITX_IOCTL_CMD, &tee_ioctl);
    } else {
        tloge("Invalid command!\n");
    }

    if (ret != HI_SUCCESS) {
        tloge("Invoke command[0x%x] failed, ret[0x%x]\n", commandID, ret);
    }

    return (TEE_Result)ret;
}

__DEFAULT hi_void TA_CloseSessionEntryPoint(hi_void *sessionContext)
{
    unused(sessionContext);
}

__DEFAULT hi_void TA_DestroyEntryPoint(hi_void)
{
}
