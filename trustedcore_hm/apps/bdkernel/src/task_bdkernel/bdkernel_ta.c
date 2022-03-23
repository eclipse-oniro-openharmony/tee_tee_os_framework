/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: This file contains the function required for TEE
 * Author: Xu Hangyu x00447026
 * Create: 2018-08-30
 */

#include "bdkernel_ta.h"
#include "tee_log.h"
#include "tee_ext_api.h"
#include "tee_mem_mgmt_api.h"
#include "bdkernel_initialize.h"
#include "bdkernel_handler.h"

__attribute__((visibility ("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    SLogTrace("KERNEL_TA: TA_CreateEntryPoint");

    TEE_Result res = (TEE_Result)AddCaller_CA_exec(BDKERNEL_CA_PACKAGE_NAME, ROOT_UID);
    if (res != TEE_SUCCESS) {
        SLogError("kernel_ca authenticate failed!");
        return res;
    }

    InitializeTee();
    return res;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
__attribute__((visibility ("default"))) void TA_DestroyEntryPoint(void)
{
    SLogTrace("KERNEL_TA: TA_DestroyEntryPoint");

    DestroyTee();
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
__attribute__((visibility ("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param *params, void **sessCtx)
{
    (void)paramTypes;
    (void)params;
    (void)sessCtx;
    SLogTrace("KERNEL_TA: TA_OpenSessionEntryPoint");

    return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
__attribute__((visibility ("default"))) void TA_CloseSessionEntryPoint(void *sessCtx)
{
    (void)sessCtx;
    SLogTrace("KERNEL_TA: TA_CloseSessionEntryPoitnt");
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the parameters
 * come from normal world.
 */
__attribute__((visibility ("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *sessCtx, uint32_t cmdId, uint32_t paramTypes, TEE_Param *params)
{
    SLogTrace("KERNEL_TA: TA_InvokeCommandEntryPoint");

    TEE_Result teeRes = TEE_SUCCESS;
    (void)sessCtx;

    switch (cmdId) {
        case CMD_HWAA_INIT_USER:
            teeRes = HandleKernelInitUser(paramTypes, params);
            break;
        default:
            SLogError("Not support, id = %d", cmdId);
            return TEE_ERROR_BAD_PARAMETERS;
    }
    return teeRes;
}
