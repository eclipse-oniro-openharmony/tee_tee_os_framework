/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: hsm efuse write ta
 * Author: chenyao
 * Create: 2020-07-10
 */

#include "tee_ext_api.h"
#include "tee_log.h"
#include "securec.h"

#include "hsm_ta_public.h"
#include "hsm_update_lib_api.h"
#include "efuse_ta_api.h"
#include "efuse_ta.h"

/* ----------------------------------------------------------------
 *   Trusted Application Entry Points
 * ----------------------------------------------------------------
 *  Function TA_CreateEntryPoint
 *  Description:
 *    The function TA_CreateEntryPoint is the Trusted Application's
 *    constructor, which the Framework calls when it creates a new
 *    instance of the Trusted Application.
 */
__attribute__((visibility ("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    tlogd("Hello efuse.\n");

    ret = AddCaller_TA_all();
    if (ret != TEE_SUCCESS) {
        SLogError("fimware addcaller ta failed, 0x%x.\n", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(HSM_EFUSE_CA, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add efuse ca root error, 0x%x.\n", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(HSM_EFUSE_CA, HWHIAIUSER_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add efuse ca hwhiaiuser error, 0x%x.\n", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(HSM_FUZZ_CA, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add fuzz ca error, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

/**
 *  Function TA_OpenSessionEntryPoint
 *  Description
 *    The Framework calls the function TA_OpenSessionEntryPoint
 *    when a client requests to open a session with the Trusted Application.
 *    The open session request may result in a new Trusted Application instance
 *    being created.
 */
__attribute__((visibility ("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
    TEE_Param params[OPEN_SESSION_PARA_NUM], void **sessionContext)
{
    TEE_Result ret;
    uint32_t dev_num = 0;

    SLogTrace("---- TA_OpenSessionEntryPoint -------- ");

    (void)paramTypes;  /* -Wunused-parameter */
    (void)params;  /* -Wunused-parameter */
    (void)sessionContext;  /* -Wunused-parameter */

    ret = lib_get_device_num(&dev_num);
    if (ret != TEE_SUCCESS) {
        SLogError("get device num fail, 0x%x\n", ret);
        return TEE_ERROR_BAD_STATE;
    }

    efuse_set_dev_id(dev_num);

    return TEE_SUCCESS;
}

STATIC uint32_t ta_write_efuse(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    uint32_t ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[HSM_INDEX2_EFUSE].memref.size == 0) {
        SLogError("Bad expected parameter.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_efuse_write(params[0].value.a, params[1].value.a, params[1].value.b,
                          params[HSM_INDEX2_EFUSE].memref.buffer, params[HSM_INDEX2_EFUSE].memref.size,
                          params[HSM_INDEX3_EFUSE].value.a);
    if (ret != TEE_SUCCESS) {
        SLogError("efuse write fail, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("write efuse success.\n");

    return TEE_SUCCESS;
}

STATIC uint32_t ta_burn_efuse(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    uint32_t ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_efuse_burn(params[0].value.a, params[0].value.b);
    if (ret != TEE_SUCCESS) {
        SLogError("burn efuse fail, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("burn efuse success.\n");

    return TEE_SUCCESS;
}

STATIC uint32_t ta_check_efuse(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    uint32_t ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[HSM_INDEX2_EFUSE].memref.size == 0) {
        SLogError("Bad expected parameter.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_efuse_check(params[0].value.a, params[1].value.a, params[1].value.b,
                          params[HSM_INDEX2_EFUSE].memref.buffer, params[HSM_INDEX2_EFUSE].memref.size,
                          params[HSM_INDEX3_EFUSE].value.a);
    if (ret != TEE_SUCCESS) {
        SLogError("efuse check fail, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("check efuse success.\n");

    return TEE_SUCCESS;
}

/**
 *  Function TA_InvokeCommandEntryPoint
 *  Description
 *    The Framework calls this function when the client invokes a command
 *    within the given session.
 */
__attribute__((visibility ("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext,
    uint32_t cmd_id, uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    SLogTrace("---- TA_InvokeCommandEntryPoint ----------- ");

    (void)paramTypes;  /* -Wunused-parameter */
    (void)sessionContext;  /* -Wunused-parameter */

    switch (cmd_id) {
        case HSM_SEC_EFUSE_WRITE_CMD:
            return ta_write_efuse(paramTypes, params);
        case HSM_SEC_EFUSE_BURN_CMD:
            return ta_burn_efuse(paramTypes, params);
        case HSM_SEC_EFUSE_CHECK_CMD:
            return ta_check_efuse(paramTypes, params);
        default:
            SLogError("Unknown CMD ID: %x", cmd_id);
            break;
    }

    return TEE_ERROR_NOT_SUPPORTED;
}

/**
 *  Function TA_CloseSessionEntryPoint
 *  Description:
 *    The Framework calls this function to close a client session.
 *    During the call to this function the implementation can use
 *    any session functions.
 */
__attribute__((visibility ("default"))) void TA_CloseSessionEntryPoint(void *sessionContext)
{
    SLogTrace("---- TA_CloseSessionEntryPoint ----- ");

    (void)sessionContext;  /* -Wunused-parameter */
}
