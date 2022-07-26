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

#include <securec.h>
#include <string.h>
#include <tee_core_api.h>
#include <tee_ext_api.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <tee_property_api.h>
#include <test_tcf_cmdid.h>
#include <test_comm_cmdid.h>

#define CA_PKGN_VENDOR "/vendor/bin/tee_test_tcf"
#define CA_PKGN_SYSTEM "/system/bin/tee_test_tcf"
#define CA_UID 0

#define BOOLEAN_TRUE "true"
#define BOOLEAN_FALSE "false"
#define GPD_TA_DATASIZE "gpd.ta.dataSize"
#define GPD_TA_STACKSIZE "gpd.ta.stackSize"
#define VALUE_PREDEFINED_DATASIZE 819200
#define VALUE_PREDEFINED_STACKSIZE 81920
#define PROPERTY_NAME_MAX_SIZE 100
#define PROPERTY_OUTPUT_STRING_MAX_SIZE 200
#define DEFAULT_BUFFER_SIZE 1024
#define PROPERTY_OUTPUT_BINARY_BLOCK_MAX_SIZE 200
#define MAXLEN_U32 11
#define MAXLEN_U64 21
#define SMC_TA_TESTUUID_TIMELOW 0x534D4152
#define SMC_TA_TESTUUID_TIMEMID 0x542D
#define SMC_TA_TESTUUID_TIMEHIANDVERSION 0x4353
#define SMC_TA_TESTUUID_CLOCKSEQANDNODE                \
    {                                                  \
        0x4c, 0x54, 0xd3, 0x01, 0x6a, 0x17, 0x1f, 0x01 \
    }

#define SMC_TA_TESTIDENTITY_LOGIN 0xF0000000
#define SMC_TA_TESTIDENTITY_TIMELOW 0x01010101
#define SMC_TA_TESTIDENTITY_TIMEMID 0x2020
#define SMC_TA_TESTIDENTITY_TIMEHIANDVERSION 0x0303
#define SMC_TA_TESTIDENTITY_CLOCKSEQANDNODE            \
    {                                                  \
        0x40, 0x40, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05 \
    }

#define ENUMERATOR1 1
#define MAX_ENUMERATOR 1023

char *g_teeOutput = "TEEMEM_OUTPUT";
char *g_teeInout = "the param is TEEMEM_INOUT";
uint32_t g_teeOutputLen;
uint32_t g_teeInoutLen;

TEE_Result CmdTEEGetPropertyAsString(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_PropSetHandle nPropSet;
    char *pPropName = NULL;
    char *pOutputName = NULL;
    uint32_t caseId;
    TEE_Result cmdResult;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||   // the property set
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) ||  // the property name
        (TEE_PARAM_TYPE_GET(nParamTypes, 2) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) { // the output value
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nPropSet = (TEE_PropSetHandle)pParams[0].value.a;
    caseId = pParams[0].value.b;
    pPropName = pParams[1].memref.buffer;
    pOutputName = pParams[2].memref.buffer;

    if (caseId == OUTPUTBUFFERSIZE_ISZERO)
        pParams[2].memref.size = 0;
    else if (caseId == OUTPUTBUFFERSIZE_TOOSHORT)
        pParams[2].memref.size = 1;

    switch (caseId) {
        case INPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsString(nPropSet, NULL, pOutputName, &pParams[2].memref.size);
            break;
        case OUTPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsString(nPropSet, pPropName, NULL, &pParams[2].memref.size);
            break;
        case OUTPUTBUFFERSIZE_ISNULL:
            cmdResult = TEE_GetPropertyAsString(nPropSet, pPropName, pOutputName, NULL);
            break;
        default:
            if (nPropSet >= ENUMERATOR1 && nPropSet <= MAX_ENUMERATOR)
                cmdResult = TEE_GetPropertyAsString(nPropSet, NULL, pOutputName, &pParams[2].memref.size);
            else
                cmdResult = TEE_GetPropertyAsString(nPropSet, pPropName, pOutputName, &pParams[2].memref.size);
            break;
    }

    tlogi("after TEE_GetPropertyAsString, pPropName=%s, pParams[1].memref.size=0x%x", pPropName,
        pParams[1].memref.size);
    tlogi("after TEE_GetPropertyAsString, pOutputName=%s, pParams[2].memref.size=0x%x", pOutputName,
        pParams[2].memref.size);
    return cmdResult;
}

TEE_Result CmdTEEGetPropertyAsBool(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_PropSetHandle nPropSet;
    char *pPropName = NULL;
    bool nOutputBool;
    uint32_t caseId;
    TEE_Result cmdResult;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||   // the property set
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) ||  // the property name
        (TEE_PARAM_TYPE_GET(nParamTypes, 2) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) { // the output value
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nPropSet = (TEE_PropSetHandle)pParams[0].value.a;
    caseId = pParams[0].value.b;
    pPropName = pParams[1].memref.buffer;

    switch (caseId) {
        case INPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsBool(nPropSet, NULL, &nOutputBool);
            break;
        case OUTPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsBool(nPropSet, pPropName, NULL);
            break;
        default:
            if (nPropSet >= ENUMERATOR1 && nPropSet <= MAX_ENUMERATOR)
                cmdResult = TEE_GetPropertyAsBool(nPropSet, NULL, &nOutputBool);
            else
                cmdResult = TEE_GetPropertyAsBool(nPropSet, pPropName, &nOutputBool);
            break;
    }

    if ((nOutputBool == true) && (cmdResult == TEE_SUCCESS)) {
        TEE_MemMove(pParams[2].memref.buffer, BOOLEAN_TRUE, sizeof(BOOLEAN_TRUE));
        pParams[2].memref.size = sizeof(BOOLEAN_TRUE);
    } else {
        TEE_MemMove(pParams[2].memref.buffer, BOOLEAN_FALSE, sizeof(BOOLEAN_FALSE));
        pParams[2].memref.size = sizeof(BOOLEAN_FALSE);
    }

    return cmdResult;
}

TEE_Result CmdTEEGetPropertyAsU32(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_PropSetHandle nPropSet;
    char *pPropName = NULL;
    uint32_t nIntResult;
    uint32_t caseId;
    char outStr[MAXLEN_U32] = { 0 };
    TEE_Result cmdResult;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||   // the property set
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) ||  // the property name
        (TEE_PARAM_TYPE_GET(nParamTypes, 2) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) { // the output value
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nPropSet = (TEE_PropSetHandle)pParams[0].value.a;
    caseId = pParams[0].value.b;
    pPropName = pParams[1].memref.buffer;

    switch (caseId) {
        case INPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsU32(nPropSet, NULL, &nIntResult);
            break;
        case OUTPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsU32(nPropSet, pPropName, NULL);
            break;
        default:
            if (nPropSet >= ENUMERATOR1 && nPropSet <= MAX_ENUMERATOR)
                cmdResult = TEE_GetPropertyAsU32(nPropSet, NULL, &nIntResult);
            else
                cmdResult = TEE_GetPropertyAsU32(nPropSet, pPropName, &nIntResult);
            break;
    }

    sprintf(outStr, "%d", nIntResult);
    TEE_MemMove(pParams[2].memref.buffer, outStr, strlen(outStr) + 1);
    pParams[2].memref.size = strlen(outStr) + 1;

    return cmdResult;
}

TEE_Result CmdTEEGetPropertyAsU64(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_PropSetHandle nPropSet;
    char *pPropName = NULL;
    char outStr[MAXLEN_U64] = { 0 };
    uint64_t nIntResult;
    uint32_t caseId;
    TEE_Result cmdResult;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||   // the property set
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) ||  // the property name
        (TEE_PARAM_TYPE_GET(nParamTypes, 2) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) { // the output value
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nPropSet = (TEE_PropSetHandle)pParams[0].value.a;
    caseId = pParams[0].value.b;
    pPropName = pParams[1].memref.buffer;

    switch (caseId) {
        case INPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsU64(nPropSet, NULL, &nIntResult);
            break;
        case OUTPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsU64(nPropSet, pPropName, NULL);
            break;
        default:
            if (nPropSet >= ENUMERATOR1 && nPropSet <= MAX_ENUMERATOR)
                cmdResult = TEE_GetPropertyAsU64(nPropSet, NULL, &nIntResult);
            else
                cmdResult = TEE_GetPropertyAsU64(nPropSet, pPropName, &nIntResult);
            break;
    }

    sprintf(outStr, "%lld", nIntResult);
    TEE_MemMove(pParams[2].memref.buffer, outStr, strlen(outStr) + 1);
    pParams[2].memref.size = strlen(outStr) + 1;

    return cmdResult;
}

TEE_Result CmdTEEGetPropertyAsBinaryBlock(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_PropSetHandle nPropSet;
    char *pPropName = NULL;
    void *pOutputBinaryBlock = NULL;
    uint32_t caseId;
    TEE_Result cmdResult;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||   // the property set
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) ||  // the property name
        (TEE_PARAM_TYPE_GET(nParamTypes, 2) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) { // the output value
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nPropSet = (TEE_PropSetHandle)pParams[0].value.a;
    caseId = pParams[0].value.b;
    pPropName = pParams[1].memref.buffer;
    pOutputBinaryBlock = pParams[2].memref.buffer;
    if (caseId == OUTPUTBUFFERSIZE_ISZERO)
        pParams[2].memref.size = 0;
    else if (caseId == OUTPUTBUFFERSIZE_TOOSHORT)
        pParams[2].memref.size = 1;

    switch (caseId) {
        case INPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsBinaryBlock(nPropSet, NULL, pOutputBinaryBlock, &pParams[2].memref.size);
            break;
        case OUTPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsBinaryBlock(nPropSet, pPropName, NULL, &pParams[2].memref.size);
            break;
        case OUTPUTBUFFERSIZE_ISNULL:
            cmdResult = TEE_GetPropertyAsBinaryBlock(nPropSet, pPropName, pOutputBinaryBlock, NULL);
            break;
        default:
            if (nPropSet >= ENUMERATOR1 && nPropSet <= MAX_ENUMERATOR)
                cmdResult = TEE_GetPropertyAsBinaryBlock(nPropSet, NULL, pOutputBinaryBlock, &pParams[2].memref.size);
            else
                cmdResult =
                    TEE_GetPropertyAsBinaryBlock(nPropSet, pPropName, pOutputBinaryBlock, &pParams[2].memref.size);
            break;
    }

    return cmdResult;
}

TEE_Result CmdTEEGetPropertyAsUUID(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_PropSetHandle nPropSet;
    char *pPropName = NULL;
    char nClockSeqAndNode[8] = SMC_TA_TESTUUID_CLOCKSEQANDNODE;
    TEE_UUID nResultUUID;
    uint32_t caseId;
    TEE_Result cmdResult;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||   // the property set
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) ||  // the property name
        (TEE_PARAM_TYPE_GET(nParamTypes, 2) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) { // the output value
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nPropSet = (TEE_PropSetHandle)pParams[0].value.a;
    caseId = pParams[0].value.b;
    pPropName = pParams[1].memref.buffer;

    switch (caseId) {
        case INPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsUUID(nPropSet, NULL, &nResultUUID);
            break;
        case OUTPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsUUID(nPropSet, pPropName, NULL);
            break;
        default:
            if (nPropSet >= ENUMERATOR1 && nPropSet <= MAX_ENUMERATOR)
                cmdResult = TEE_GetPropertyAsUUID(nPropSet, NULL, &nResultUUID);
            else
                cmdResult = TEE_GetPropertyAsUUID(nPropSet, pPropName, &nResultUUID);
            break;
    }

    // no need to update the buffer length as the result is a UUID.
    // it is the responsibility of the Client app to provide an output buffer large enough to handle a UUID
    if ((cmdResult == TEE_SUCCESS) && (strncmp(pPropName, "gpd.tee.deviceID", strlen(pPropName)) != 0)) {
        if ((nResultUUID.timeLow == (uint32_t)SMC_TA_TESTUUID_TIMELOW) &&
            (nResultUUID.timeMid == (uint16_t)SMC_TA_TESTUUID_TIMEMID) &&
            (nResultUUID.timeHiAndVersion == (uint16_t)SMC_TA_TESTUUID_TIMEHIANDVERSION) &&
            (TEE_MemCompare(&nResultUUID.clockSeqAndNode, nClockSeqAndNode, 8) == 0)) {
            tlogi("TEE_GetPropertyAsUUID success and get uuid is correct!");
        } else {
            tloge("TEE_GetPropertyAsUUID get uuid is wrong!");
            cmdResult = TEE_ERROR_GENERIC;
        }
    }
    return cmdResult;
}

TEE_Result CmdTEEAllocatePropertyEnumerator(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_Result cmdResult;
    TEE_PropSetHandle nPropSet;
    uint32_t caseId;

    if (TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_OUTPUT) {
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nPropSet = (TEE_PropSetHandle)pParams[0].value.a;
    caseId = pParams[0].value.b;

    if (caseId != OUTPUT_ISNULL) {
        cmdResult = TEE_AllocatePropertyEnumerator(&nPropSet);
    } else {
        cmdResult = TEE_AllocatePropertyEnumerator(NULL);
    }
    pParams[0].value.a = nPropSet;

    return cmdResult;
}

TEE_Result CmdTEEStartPropertyEnumerator(uint32_t nParamTypes, TEE_Param pParams[4])
{
    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT)) {
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    TEE_StartPropertyEnumerator((TEE_PropSetHandle)pParams[0].value.a, (TEE_PropSetHandle)pParams[1].value.a);
    tlogi("test TEE_StartPropertyEnumerator is finish!\n");
    return TEE_SUCCESS;
}

TEE_Result CmdTEEEnumeratorOperate(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_Result cmdResult;
    TEE_PropSetHandle nPropSet;
    uint32_t cmd;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT)) {
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nPropSet = (TEE_PropSetHandle)pParams[0].value.a;
    cmd = pParams[0].value.b;

    switch (cmd) {
        case GET_TCF_CMDID(CMD_TEE_FreePropertyEnumerator):
            TEE_FreePropertyEnumerator(nPropSet);
            tlogi("test TEE_FreePropertyEnumerator is finish!\n");
            return TEE_SUCCESS;
        case GET_TCF_CMDID(CMD_TEE_ResetPropertyEnumerator):
            TEE_ResetPropertyEnumerator(nPropSet);
            tlogi("test TEE_ResetPropertyEnumerator is finish!\n");
            return TEE_SUCCESS;
        case GET_TCF_CMDID(CMD_TEE_GetNextPropertyEnumerator):
            cmdResult = TEE_GetNextProperty(nPropSet);
            break;
        default:
            tloge("invalid test cmd! cmdId: 0x%x", cmd);
            cmdResult = TEE_ERROR_GENERIC;
            break;
    }

    return cmdResult;
}

TEE_Result CmdTEEGetPropertyName(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_Result cmdResult;
    TEE_PropSetHandle nPropSet;
    uint32_t caseId;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||   // enumerator
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) { // property set
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nPropSet = (TEE_PropSetHandle)pParams[0].value.a;
    caseId = pParams[0].value.b;
    if (caseId == OUTPUTBUFFERSIZE_TOOSHORT)
        pParams[1].memref.size = 1;

    switch (caseId) {
        case OUTPUT_ISNULL:
            cmdResult = TEE_GetPropertyName(nPropSet, NULL, &pParams[1].memref.size);
            break;
        case OUTPUTBUFFERSIZE_ISNULL:
            cmdResult = TEE_GetPropertyName(nPropSet, pParams[1].memref.buffer, NULL);
            break;
        default:
            cmdResult = TEE_GetPropertyName(nPropSet, pParams[1].memref.buffer, &pParams[1].memref.size);
            break;
    }

    tlogi("after TEE_GetPropertyName, pParams[0].value.a=0x%x, cmdResult=0x%x", pParams[0].value.a, cmdResult);
    tlogi("after TEE_GetPropertyName, pParams[1].memref.buffer=%s, pParams[1].memref.size=0x%x",
        pParams[1].memref.buffer, pParams[1].memref.size);
    return cmdResult;
}

void getUUIDFromBuffer(TEE_UUID *pTargetUUID, char uuidvalue[16])
{
    (*pTargetUUID).timeLow = (uint32_t)(uuidvalue[0] << 24) + (uint32_t)(uuidvalue[1] << 16) +
        (uint32_t)(uuidvalue[2] << 8) + (uint32_t)(uuidvalue[3]);
    (*pTargetUUID).timeMid = (uint32_t)(uuidvalue[4] << 8) + (uint32_t)(uuidvalue[5]);
    (*pTargetUUID).timeHiAndVersion = (uint32_t)(uuidvalue[6] << 8) + (uint32_t)(uuidvalue[7]);
    (*pTargetUUID).clockSeqAndNode[0] = (uint8_t)(uuidvalue[8]);
    (*pTargetUUID).clockSeqAndNode[1] = (uint8_t)(uuidvalue[9]);
    (*pTargetUUID).clockSeqAndNode[2] = (uint8_t)(uuidvalue[10]);
    (*pTargetUUID).clockSeqAndNode[3] = (uint8_t)(uuidvalue[11]);
    (*pTargetUUID).clockSeqAndNode[4] = (uint8_t)(uuidvalue[12]);
    (*pTargetUUID).clockSeqAndNode[5] = (uint8_t)(uuidvalue[13]);
    (*pTargetUUID).clockSeqAndNode[6] = (uint8_t)(uuidvalue[14]);
    (*pTargetUUID).clockSeqAndNode[7] = (uint8_t)(uuidvalue[15]);
}

TEE_Result CmdTEEOpenTASession(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_UUID pTargetUUID;
    TEE_Param pTargetParams[4];
    uint32_t nLocalParamTypes = 0;
    uint32_t nReturnOrigin = 0;
    TEE_TASessionHandle nsession;
    TEE_Result nTmpResult;
    uint32_t caseId;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||  /* Command to pass to the TA */
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) || /* UUID in a buffer */
        (TEE_PARAM_TYPE_GET(nParamTypes, 2) != TEE_PARAM_TYPE_VALUE_OUTPUT)) { /* return origin of the OpenTASession */
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    if (pParams[1].memref.size != 16) {
        tloge("CmdProcessInvokeTAInvoke_simple: UUID size not correct");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    caseId = pParams[0].value.a;
    getUUIDFromBuffer(&pTargetUUID, (char *)pParams[1].memref.buffer);

    nLocalParamTypes =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    /* Open the session */
    if (caseId == INPUT_ISNULL)
        nTmpResult =
            TEE_OpenTASession(NULL, TEE_TIMEOUT_INFINITE, nLocalParamTypes, pTargetParams, &nsession, &nReturnOrigin);
    else if (caseId == RETURNORIGIN_ISNULL)
        nTmpResult =
            TEE_OpenTASession(&pTargetUUID, TEE_TIMEOUT_INFINITE, nLocalParamTypes, pTargetParams, &nsession, NULL);
    else if (caseId == OUTPUT_ISNULL)
        nTmpResult = TEE_OpenTASession(&pTargetUUID, TEE_TIMEOUT_INFINITE, nLocalParamTypes, pTargetParams, NULL,
            &nReturnOrigin);
    else
        nTmpResult = TEE_OpenTASession(&pTargetUUID, TEE_TIMEOUT_INFINITE, nLocalParamTypes, pTargetParams, &nsession,
            &nReturnOrigin);

    tlogi("test TEE_OpenTASession is success!\n");

    return nTmpResult;
}

static TEE_Result TestTypeBuffer(uint32_t paramTypes, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;

    if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT) {
        tloge("%s: Bad expected parameter types\n", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    g_teeOutputLen = strlen(g_teeOutput) + 1;
    g_teeInoutLen = strlen(g_teeInout) + 1;

    for (uint32_t i = 0; i < 4; i++) {
        uint32_t param_type = TEE_PARAM_TYPE_GET(paramTypes, i);
        switch (param_type) {
            case TEE_PARAM_TYPE_MEMREF_INPUT:
            case TEE_PARAM_TYPE_MEMREF_OUTPUT:
                tlogi("param %d is TEE_PARAM_TYPE_MEMREF_INPUT or TEE_PARAM_TYPE_MEMREF_OUTPUT\n", i);
                tlogi("before modify,param %d size=%d, val=%s\n", i, params[i].memref.size, params[i].memref.buffer);
                TEE_MemMove(params[i].memref.buffer, g_teeOutput, g_teeOutputLen);
                params[i].memref.size = g_teeOutputLen;
                tlogi("after modify,param %d size=%d, val=%s\n", i, params[i].memref.size, params[i].memref.buffer);
                break;
            case TEE_PARAM_TYPE_MEMREF_INOUT:
                tlogi("param %d is TEE_PARAM_TYPE_MEMREF_INOUT\n", i);
                tlogi("before modify,param %d size=%d, val=%s\n", i, params[i].memref.size, params[i].memref.buffer);
                TEE_MemMove(params[i].memref.buffer, g_teeInout, g_teeInoutLen);
                params[i].memref.size = g_teeInoutLen;
                tlogi("after modify,param %d size=%d, val=%s\n", i, params[i].memref.size, params[i].memref.buffer);
                break;
            case TEE_PARAM_TYPE_VALUE_INPUT:
            case TEE_PARAM_TYPE_VALUE_OUTPUT:
            case TEE_PARAM_TYPE_VALUE_INOUT:
            case TEE_PARAM_TYPE_NONE:
                break;
            default:
                break;
        }
    }

    return ret;
}

TEE_Result CmdTEEMalloc(uint32_t nParamTypes, TEE_Param pParams[4])
{
    size_t nSize;
    uint32_t nHint;
    char *pBuffer = NULL;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nSize = pParams[0].value.a;
    nHint = pParams[0].value.b;

    tlogi("before TEE_Malloc nSize=%d, nHint=%d\n", nSize, nHint);
    pBuffer = (char *)TEE_Malloc(nSize, nHint);

    if (pBuffer == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    } else {
        tlogi("test TEE_Malloc is success!\n");
        TEE_MemMove(pParams[1].memref.buffer, pBuffer, nSize);
        TEE_Free((void *)pBuffer); // free the allocated buffer
        tlogi("TEE_Free is finish!\n");
        return TEE_SUCCESS;
    }
}

TEE_Result CmdTEERealloc(uint32_t nParamTypes, TEE_Param pParams[4])
{
    char *pBufferMalloc = NULL;
    char *pBufferRealloc = NULL;
    uint32_t i;
    char buf[DEFAULT_BUFFER_SIZE] = { 0 };

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
        (TEE_PARAM_TYPE_GET(nParamTypes, 2) != TEE_PARAM_TYPE_VALUE_OUTPUT) ||
        (TEE_PARAM_TYPE_GET(nParamTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) {
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    size_t nOldSize = pParams[0].value.a;
    size_t nNewSize = pParams[0].value.b;
    uint32_t caseId = pParams[3].value.a;

    pBufferMalloc = (char *)TEE_Malloc(nOldSize, 0);
    if (pBufferMalloc == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    (void)memset_s(pBufferMalloc, nOldSize, 0x41, nOldSize); // 'A' is 0x41

    pBufferRealloc = (char *)TEE_Realloc(buf, 10000);

    if (caseId == BUFFER_IS_FREE)
        TEE_Free((void *)pBufferMalloc); // free the allocated buffer

    if (caseId == INPUT_ISNULL)
        pBufferRealloc = (char *)TEE_Realloc(NULL, nNewSize);
    else if (caseId == BUFFER_ISNOT_MALLOC)
        pBufferRealloc = (char *)TEE_Realloc(buf, nNewSize);
    else
        pBufferRealloc = (char *)TEE_Realloc((void *)pBufferMalloc, nNewSize);

    if (pBufferRealloc == NULL) {
        if (pBufferMalloc != NULL) {
            for (i = 0; i < nOldSize; i++) {
                if (pBufferMalloc[i] != (char)'A') { // checks that the data has not been changed after realloc
                    tloge("%d th bytes of pBufferMalloc is not correct, it is %c\n", i + 1, pBufferMalloc[i]);
                    TEE_Free((void *)pBufferMalloc); // free the allocated buffer
                    return TEE_ERROR_GENERIC;
                }
            }
            TEE_Free((void *)pBufferMalloc); // free the allocated buffer
        }
        return TEE_ERROR_OUT_OF_MEMORY;
    } else {
        pParams[2].value.a = (uint32_t)pBufferMalloc;
        pParams[2].value.b = (uint32_t)pBufferRealloc;
        if (caseId == INPUT_ISNULL)
            TEE_MemMove(pParams[1].memref.buffer, pBufferMalloc, nOldSize);
        else
            TEE_MemMove(pParams[1].memref.buffer, pBufferRealloc, (nOldSize < nNewSize ? nOldSize : nNewSize));

        TEE_Free((void *)pBufferRealloc); // free the reallocated buffer
        if (pBufferMalloc != NULL)
            TEE_Free((void *)pBufferMalloc); // free the allocated buffer
        return TEE_SUCCESS;
    }
}

TEE_Result CmdTEEPanic(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_Result panicCode;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT))
        panicCode = pParams[0].value.a;
    else
        panicCode = TEE_ERROR_BAD_PARAMETERS;

    TEE_Panic(panicCode);
    return TEE_SUCCESS;
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
    (void)sessionContext;
    tlogi("---- TA_OpenSessionEntryPoint --------");
    g_teeInoutLen = strlen(g_teeInout) + 1;

    TEE_MemMove(params[1].memref.buffer, g_teeInout, g_teeInoutLen);
    params[1].memref.size = g_teeInoutLen;

    if (params[0].value.a == TA_CRASH_FLAG)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

    return TEE_SUCCESS;
}

typedef TEE_Result (*func)(uint32_t nParamTypes, TEE_Param pParams[4]);

struct testFunc {
    uint32_t cmdId;
    func funcName;
};

struct testFunc g_testTable[] = {
    { GET_TCF_CMDID(CMD_TEE_GetPropertyAsString), CmdTEEGetPropertyAsString },
    { GET_TCF_CMDID(CMD_TEE_GetPropertyAsBool), CmdTEEGetPropertyAsBool },
    { GET_TCF_CMDID(CMD_TEE_GetPropertyAsU32), CmdTEEGetPropertyAsU32 },
    { GET_TCF_CMDID(CMD_TEE_GetPropertyAsU64), CmdTEEGetPropertyAsU64 },
    { GET_TCF_CMDID(CMD_TEE_GetPropertyAsBinaryBlock), CmdTEEGetPropertyAsBinaryBlock },
    { GET_TCF_CMDID(CMD_TEE_GetPropertyAsUUID), CmdTEEGetPropertyAsUUID },
    { GET_TCF_CMDID(CMD_TEE_AllocatePropertyEnumerator), CmdTEEAllocatePropertyEnumerator },
    { GET_TCF_CMDID(CMD_TEE_StartPropertyEnumerator), CmdTEEStartPropertyEnumerator },
    { GET_TCF_CMDID(CMD_TEE_FreePropertyEnumerator), CmdTEEEnumeratorOperate },
    { GET_TCF_CMDID(CMD_TEE_ResetPropertyEnumerator), CmdTEEEnumeratorOperate },
    { GET_TCF_CMDID(CMD_TEE_GetNextPropertyEnumerator), CmdTEEEnumeratorOperate },
    { GET_TCF_CMDID(CMD_TEE_GetPropertyNameEnumerator), CmdTEEGetPropertyName },
    { GET_TCF_CMDID(CMD_TEE_OpenTASession), CmdTEEOpenTASession },
    { GET_COMM_CMDID(TEE_TEST_BUFFER), TestTypeBuffer },
    { GET_TCF_CMDID(CMD_TEE_Malloc), CmdTEEMalloc },
    { GET_TCF_CMDID(CMD_TEE_Realloc), CmdTEERealloc },
    { GET_TCF_CMDID(CMD_TEE_Panic), CmdTEEPanic },
};

uint32_t g_testTableSize = sizeof(g_testTable) / sizeof(g_testTable[0]);

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t cmd, uint32_t parmType, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;
    (void)sessionContext;
    uint32_t i;
    tlogi("---- TA invoke command ----------- command id: 0x%x", cmd);

    for (i = 0; i < g_testTableSize; i++) {
        if (cmd == g_testTable[i].cmdId) {
            ret = g_testTable[i].funcName(parmType, params);
            if (ret != TEE_SUCCESS) {
                tloge("invoke command with cmdId: 0x%x failed! ret: 0x%x", cmd, ret);
            } else {
                tlogi("invoke command with cmdId: 0x%x success! ret: 0x%x", cmd, ret);
            }
            return ret;
        }
    }

    tloge("not support this invoke command! cmdId: 0x%x", cmd);
    return TEE_ERROR_GENERIC;
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
