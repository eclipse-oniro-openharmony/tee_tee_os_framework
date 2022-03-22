/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: This file mainly deal with input command initially.
 * Create: 2020-06-28
 */

#include "tee_mem_mgmt_api.h"
#include "tee_core_api.h"
#include "kds_defs.h"
#include "kds_core.h"
#include "kds_phase1.h"
#include "kds_phase2.h"
#include "kds_phase3.h"

#define CLIENT_APPLICATION_NAME_HIDL "/vendor/bin/hw/vendor.huawei.hardware.kds@1.0-service"
#define CLIENT_APPLICATION_NAME_UID 1000 /* 0 means root, 1000 means system */

#define KDS_API_EXPORT __attribute__((visibility("default")))

KDS_API_EXPORT TEE_Result TA_CreateEntryPoint(void)
{
    SLogTrace("------ kds: TA_CreateEntryPoint -------");
    TEE_Result ret = AddCaller();
    if (ret != TEE_SUCCESS) {
        SLogError("AddCaller_CA_exec failed");
        return ret;
    }

    ret = AddCaller_CA_exec(CLIENT_APPLICATION_NAME_HIDL, CLIENT_APPLICATION_NAME_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add client hidl failed");
        return ret;
    }

    ret = AddCaller_TA_all();
    if (ret != TEE_SUCCESS) {
        SLogError("AddCaller_TA_all failed\n");
        return ret;
    }
    return TEE_SUCCESS;
}

KDS_API_EXPORT TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
    TEE_Param *params, void **sessionContext)
{
    SLogTrace("------- kds: TA_OpenSessionEntryPoint --------");
    (void)paramTypes;
    (void)params;
    (void)sessionContext;
    return TEE_SUCCESS;
}

static KdsResultCode EntryAccessCheck()
{
    caller_info callerInfo = {0};

    TEE_Result ret = TEE_EXT_GetCallerInfo(&callerInfo, sizeof(caller_info));
    if (ret != TEE_SUCCESS) {
        SLogError("TEE_EXT_GetCallerInfo failed, ret %x\n", ret);
        return KDS_FAIL;
    }

    if (callerInfo.session_type == SESSION_FROM_CA) {
        SLogTrace("CA go to switch case");
        return KDS_CA_ACCESS;
    } else if (callerInfo.session_type == SESSION_FROM_TA) {
        SLogTrace("TA go to switch case");
        return KDS_TA_ACCESS;
    } else {
        return KDS_ERR_BAD_ACCESS;
    }
}

static TEE_Result HandleCaCommand(uint32_t nCommandID, uint32_t paramTypes, TEE_Param *params)
{
    TEE_Result ret;

    switch (nCommandID) {
        case KDS_CMD_ID_REQ:
            ret = HandleCaCommandReq(paramTypes, params);
            if (ret != TEE_SUCCESS) {
                SLogError("HandleCaCommandReq failed ret=0x%x\n", ret);
            }
            break;
        case KDS_CMD_CA_GID_REQ:
            ret = HandleGidCommandFromCa(paramTypes, params);
            if (ret != TEE_SUCCESS) {
                SLogError("HandleGidCommandFromCa ret=0x%x\n", ret);
            }
            break;
        default:
            SLogError("invalid ca cmd:%x", nCommandID);
            ret = TEE_ERROR_INVALID_CMD;
            break;
    }
    return ret;
}

static TEE_Result HandleTaCommand(uint32_t nCommandID, uint32_t paramTypes, TEE_Param *params)
{
    switch (nCommandID) {
        case KDS_CMD_DECRYPT:
            return HandleTaCommandDecrypt(paramTypes, params);
        default:
            SLogError("invalid ta cmd:%x", nCommandID);
            return TEE_ERROR_INVALID_CMD;
    }
}

KDS_API_EXPORT TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandId,
    uint32_t paramTypes, TEE_Param *params)
{
    SLogTrace("----- kds: TA_InvokeCommandEntryPoint -----");
    KdsResultCode accessRet = EntryAccessCheck();
    (void)sessionContext;

    if (accessRet == KDS_CA_ACCESS) {
        return HandleCaCommand(commandId, paramTypes, params);
    }
    if (accessRet == KDS_TA_ACCESS) {
        return HandleTaCommand(commandId, paramTypes, params);
    }
    SLogError("Invalid ret: %x", accessRet);
    return TEE_ERROR_ACCESS_DENIED;
}

KDS_API_EXPORT void TA_CloseSessionEntryPoint(void *sessionContext)
{
    SLogTrace("kds: succeed to close session");
    if (sessionContext != NULL) {
        TEE_Free(sessionContext);
    }
}

KDS_API_EXPORT void TA_DestroyEntryPoint(void)
{
    SLogTrace("kds: succeed to destroy entry point");
}