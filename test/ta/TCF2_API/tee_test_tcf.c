/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <tee_ext_api.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <tee_property_api.h>
#include <test_tcf_cmdid.h>

#define CA_PKGN_VENDOR "/vendor/bin/tee_test_tcf"
#define CA_PKGN_SYSTEM "/system/bin/tee_test_tcf"
#define CA_UID 0

#define SMC_TA_TESTIDENTITY_LOGIN 0xF0000000
#define SMC_TA_TESTIDENTITY_TIMELOW 0x01010101
#define SMC_TA_TESTIDENTITY_TIMEMID 0x2020
#define SMC_TA_TESTIDENTITY_TIMEHIANDVERSION 0x0303
#define SMC_TA_TESTIDENTITY_CLOCKSEQANDNODE            \
    {                                                  \
        0x40, 0x40, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05 \
    }

#define DEFAULT_BUFFER_SIZE 1024

TEE_Result CmdTEEGetPropertyAsIdentity_withoutEnum(uint32_t nParamTypes, TEE_Param pParams[4])
{
    /* * VARIABLES * */
    TEE_PropSetHandle nPropSet;
    char *pPropName;
    char nClockSeqAndNode[8] = SMC_TA_TESTIDENTITY_CLOCKSEQANDNODE;
    TEE_Identity nResultIdentity;
    uint32_t caseId;
    TEE_Result cmdResult;

    /* * CODE * */
    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||   // the property set
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) ||  // the property name
        (TEE_PARAM_TYPE_GET(nParamTypes, 2) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) { // the output value
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Read the input parameter */
    nPropSet = (TEE_PropSetHandle)pParams[0].value.a;
    caseId = pParams[0].value.b;
    pPropName = pParams[1].memref.buffer;

    switch (caseId) {
        case INPUTBUFFER_ISNULL:
            cmdResult = TEE_GetPropertyAsIdentity(nPropSet, NULL, &nResultIdentity);
            break;
        case OUTPUTBUFFER_ISNULL:
            cmdResult = TEE_GetPropertyAsIdentity(nPropSet, pPropName, NULL);
            break;
        default:
            cmdResult = TEE_GetPropertyAsIdentity(nPropSet, pPropName, &nResultIdentity);
            break;
    }

    if ((cmdResult == TEE_SUCCESS)) {
        if ((nResultIdentity.login == (uint32_t)SMC_TA_TESTIDENTITY_LOGIN) &&
            (nResultIdentity.uuid.timeLow == (uint32_t)SMC_TA_TESTIDENTITY_TIMELOW) &&
            (nResultIdentity.uuid.timeMid == (uint16_t)SMC_TA_TESTIDENTITY_TIMEMID) &&
            (nResultIdentity.uuid.timeHiAndVersion == (uint16_t)SMC_TA_TESTIDENTITY_TIMEHIANDVERSION) &&
            (TEE_MemCompare(&nResultIdentity.uuid.clockSeqAndNode, nClockSeqAndNode, 8) == 0)) {
            tlogi("TEE_GetPropertyAsIdentity success and get identity is correct!");
        } else {
            tlogi("TEE_GetPropertyAsUUID get identity is wrong!");
            cmdResult = TEE_ERROR_GENERIC;
        }
    }

    return cmdResult;
}

TEE_Result TA_CreateEntryPoint(void)
{
    tlogi("---- TA_CreateEntryPoint ---------");
    TEE_Result ret;

    ret = AddCaller_CA_exec(CA_PKGN_VENDOR, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("add caller failed, ret: 0x%x", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CA_PKGN_SYSTEM, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("add caller failed, ret: 0x%x", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t parmType, TEE_Param params[4], void **sessionContext)
{
    (void)parmType;
    (void)params;
    (void)sessionContext;
    tlogi("---- TA_OpenSessionEntryPoint --------");

    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t cmd, uint32_t parmType, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;
    (void)sessionContext;

    tlogi("---- TA invoke command ----------- command id: 0x%x", cmd);

    switch (cmd) {
        case GET_TCF_CMDID(CMD_TEE_GetPropertyAsIdentity):
            ret = CmdTEEGetPropertyAsIdentity_withoutEnum(parmType, params);
            break;
        default:
            tloge("not support this invoke command! cmdId: 0x%x", cmd);
            ret = TEE_ERROR_GENERIC;
            break;
    }

    if (ret != TEE_SUCCESS)
        tloge("invoke command for value failed! cmdId: 0x%x, ret: 0x%x", cmd, ret);

    return ret;
}

void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
    tlogi("---- TA_CloseSessionEntryPoint -----");
}

void TA_DestroyEntryPoint(void)
{
    tlogi("---- TA_DestroyEntryPoint ----");
}
