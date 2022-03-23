/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: decoder
 * Author: sdk
 * Create: 2019-04-22
 */

#include "vfmw_task.h"
#include "hi_tee_chip_task.h"
#include "hi_tee_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_type_dev.h"
#include "ta_vfmw_sign.h"

#define MDC_TEE_LOAD    0
#define MDC_TEE_UNLOAD  1

#define TEE_VFMW_SEC_PKGNAME          HISI_VFMW_TASK_NAME
#define VFMW_SEC_ROOT_ID              0

TEE_Result ta_vfmw_invoke_load(TEE_Param params[4]) /* total param num is 4 */
{
    TEE_Result ret;
    unsigned int load_opt = (unsigned int)params[0].value.b;  /* get first param 0: option */

    unsigned int args[] = {
        (unsigned int)params[0].value.a, /* get first param 0: fw length after sign */
        0                                /* init fw length before sign */
    };

    if (args[0] < VFMW_SG_IMAGE_MIN_LEN || args[0] > VFMW_SG_IMAGE_MAX_LEN) {
        tloge("fw len[0x%x] check fail \n", args[0]);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (load_opt == 0) { /* 0: load  1: resume */
        ret = vfmw_sign_verify(args, sizeof(args) / sizeof(unsigned int));
        if (ret != TEE_SUCCESS) {
            tloge(" vfmw_sign_verify failed, fw length %d \n", args[1]);
            return TEE_ERROR_SIGNATURE_INVALID;
        }
        params[0].value.a = hm_drv_call(HI_TEE_SYSCALL_VFMW_LOAD,
            args, ARRAY_SIZE(args));    /* get first param 0 return value */
    } else {
        params[0].value.a = hm_drv_call(HI_TEE_SYSCALL_VFMW_RELOAD,
            args, ARRAY_SIZE(args)); /* get first param 0 return value */
    }

    return TEE_SUCCESS;
}

TEE_Result ta_vfmw_invoke_unload(TEE_Param params[4]) /* total param num is 4 */
{
    unsigned int args[] = {
        (unsigned int)params[0].value.b, /* get first param 0: option */
        (unsigned int)params[0].value.a /* get first param 0: length */
    };

    params[0].value.a = hm_drv_call(HI_TEE_SYSCALL_VFMW_UNLOAD,
        args, ARRAY_SIZE(args)); /* get first param 0 return value */
    return TEE_SUCCESS;
}

__DEFAULT TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    ret = AddCaller_CA_exec(TEE_VFMW_SEC_PKGNAME, VFMW_SEC_ROOT_ID);
    if (ret != TEE_SUCCESS) {
        tlogd("check name:%s id:%d failed\n", TEE_VFMW_SEC_PKGNAME, VFMW_SEC_ROOT_ID);
        return ret;
    }

    return TEE_SUCCESS;
}

__DEFAULT TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
    TEE_Param params[4], void **sessionContext) /* total param size is 4 */
{
    HI_UNUSED(paramTypes);
    HI_UNUSED(params);
    HI_UNUSED(sessionContext);
    return TEE_SUCCESS;
}

__DEFAULT TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext,
    uint32_t commandID, uint32_t paramTypes, TEE_Param params[4]) /* total param size is 4 */
{
    TEE_Result ret;
    HI_UNUSED(sessionContext);
    HI_UNUSED(paramTypes);

    switch (commandID) {
        case MDC_TEE_LOAD: {
            ret = ta_vfmw_invoke_load(params);
            break;
        }
        case MDC_TEE_UNLOAD: {
            ret = ta_vfmw_invoke_unload(params);
            break;
        }
        default:
            tloge("Invalid command!\n");
            ret = TEE_ERROR_GENERIC;
            break;
    }

    if (ret != TEE_SUCCESS) {
        tloge("Invoke command[0x%x] failed, ret[0x%x]\n", commandID, ret);
    }

    return ret;
}

__DEFAULT void TA_CloseSessionEntryPoint(void *sessionContext)
{
    HI_UNUSED(sessionContext);
}

__DEFAULT void TA_DestroyEntryPoint(void)
{
}
