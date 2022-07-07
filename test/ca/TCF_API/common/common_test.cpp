/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <gtest/gtest.h>
#include <test_defines.h>
#include <common_test.h>
#include <securec.h>
#include <tee_client_api.h>
#include <tee_client_type.h>
#include <test_log.h>
#include <test_tcf_cmdid.h>

using namespace std;

TEEC_Context TCF1Test::context = { 0 };
TEEC_Session TCF1Test::session = { 0 };

void TCF1Test::SetUp()
{
    TEEC_Operation operation = { 0 };

    TEEC_Result ret = TEEC_InitializeContext(NULL, &context);
    ABORT_UNLESS(ret != TEEC_SUCCESS);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    TEEC_UUID uuid = TCF_API_UUID_1;
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, NULL);
    ABORT_UNLESS(ret != TEEC_SUCCESS);
}

void TCF1Test::TearDown()
{
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
}

TEEC_Context TCF2Test::context = { 0 };
TEEC_Session TCF2Test::session = { 0 };

void TCF2Test::SetUpTestCase()
{
    TEEC_Operation operation = { 0 };

    TEEC_Result ret = TEEC_InitializeContext(NULL, &context);
    ABORT_UNLESS(ret != TEEC_SUCCESS);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    TEEC_UUID uuid = TCF_API_UUID_2;
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, NULL);
    ABORT_UNLESS(ret != TEEC_SUCCESS);
}

void TCF2Test::TearDownTestCase()
{
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
}

TEEC_Context TCF1ENUM_Test::context = { 0 };
TEEC_Session TCF1ENUM_Test::session = { 0 };
// TestData TCF1ENUM_Test::value = { 0 };

void TCF1ENUM_Test::SetUpTestCase()
{
    TEEC_Operation operation = { 0 };

    TEEC_Result ret = TEEC_InitializeContext(NULL, &context);
    ABORT_UNLESS(ret != TEEC_SUCCESS);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    TEEC_UUID uuid = TCF_API_UUID_1;
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, NULL);
    ABORT_UNLESS(ret != TEEC_SUCCESS);
}

void TCF1ENUM_Test::TearDownTestCase()
{
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
}

void TCF1ENUM_Test::SetUp()
{
    TEEC_Result ret;

    // alloc PropertyEnumerator
    value.cmd = GET_TCF_CMDID(CMD_TEE_AllocatePropertyEnumerator);
    ret = Invoke_AllocatePropertyEnumerator(GetSession(), &value);
    ABORT_UNLESS(ret != TEEC_SUCCESS);
}

void TCF1ENUM_Test::TearDown()
{
    value.cmd = GET_TCF_CMDID(CMD_TEE_FreePropertyEnumerator);
    Invoke_Operate_PropertyEnumerator(GetSession(), &value);
}

TEEC_Result Invoke_GetPropertyAsX(TEEC_Context *context, TEEC_Session *session, TestData *testData)
{
    TEEC_Result result = TEEC_FAIL;
    int rc;
    TEEC_Operation operation = { 0 };
    TEEC_SharedMemory shareMemInput, shareMemOutput;

    // allocate the share memorys
    shareMemInput.size = BIG_SIZE;
    shareMemInput.flags = TEEC_MEM_INOUT;
    result = TEEC_AllocateSharedMemory(context, &shareMemInput);
    if (result != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("alloc shareMemInput fail!\n");
        return TEEC_FAIL;
    }

    shareMemOutput.size = BIG_SIZE;
    shareMemOutput.flags = TEEC_MEM_INOUT;
    result = TEEC_AllocateSharedMemory(context, &shareMemOutput);
    if (result != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("alloc shareMemOutput fail!\n");
        TEEC_ReleaseSharedMemory(&shareMemInput);
        return TEEC_FAIL;
    }

    // Invoke command
    operation.started = 1;
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE);
    if (testData->enumerator != 0)
        operation.params[0].value.a = testData->enumerator;
    else
        operation.params[0].value.a = testData->propSet;

    operation.params[0].value.b = testData->caseId;
    (void)memset_s(shareMemInput.buffer, BIG_SIZE, 0, BIG_SIZE);
    rc = memcpy_s(shareMemInput.buffer, shareMemInput.size, testData->inBuffer, testData->inBufferLen);
    if (rc != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("memcpy_s inBuffer to shareMemInput fail!\n");
        goto clean;
    }

    operation.params[1].memref.parent = &shareMemInput;
    operation.params[1].memref.size = shareMemInput.size;
    operation.params[1].memref.offset = 0;
    operation.params[2].memref.parent = &shareMemOutput;
    operation.params[2].memref.size = shareMemOutput.size;
    operation.params[2].memref.offset = 0;

    result = TEEC_InvokeCommand(session, testData->cmd, &operation, &testData->origin);
    testData->outBufferLen = operation.params[2].memref.size;
    rc = memcpy_s(testData->outBuffer, BIG_SIZE, shareMemOutput.buffer, testData->outBufferLen);
    if (rc != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("memcpy_s shareMemOutput to outBuffer fail! rc = 0x%x\n", rc);
    }

clean:
    TEEC_ReleaseSharedMemory(&shareMemInput);
    TEEC_ReleaseSharedMemory(&shareMemOutput);
    return result;
}

TEEC_Result Invoke_AllocatePropertyEnumerator(TEEC_Session *session, TestData *testData)
{
    TEEC_Result result;
    TEEC_Operation operation = { 0 };

    // Invoke command
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = 0;
    operation.params[0].value.b = testData->caseId;
    result = TEEC_InvokeCommand(session, testData->cmd, &operation, &testData->origin);

    testData->enumerator = operation.params[0].value.a;
    return result;
}

TEEC_Result Invoke_Operate_PropertyEnumerator(TEEC_Session *session, TestData *testData)
{
    TEEC_Result result;
    TEEC_Operation operation = { 0 };
    // Invoke command
    operation.started = 1;
    switch (testData->cmd) {
        case GET_TCF_CMDID(CMD_TEE_FreePropertyEnumerator):
        case GET_TCF_CMDID(CMD_TEE_ResetPropertyEnumerator):
        case GET_TCF_CMDID(CMD_TEE_GetNextPropertyEnumerator):
            operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
            operation.params[0].value.a = testData->enumerator;
            break;
        case GET_TCF_CMDID(CMD_TEE_StartPropertyEnumerator):
            operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
            operation.params[0].value.a = testData->enumerator;
            operation.params[1].value.a = testData->propSet;
            break;
        case GET_TCF_CMDID(CMD_TEE_GetPropertyNameEnumerator):
            operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
            operation.params[0].value.a = testData->enumerator;
            operation.params[0].value.b = testData->caseId;
            operation.params[1].tmpref.buffer = testData->outBuffer;
            operation.params[1].tmpref.size = testData->outBufferLen;
            break;
        default:
            TEST_PRINT_ERROR("not support this test command! cmdId: 0x%x", testData->cmd);
            return TEEC_FAIL;
    }

    result = TEEC_InvokeCommand(session, testData->cmd, &operation, &testData->origin);
    if (testData->cmd == GET_TCF_CMDID(CMD_TEE_GetPropertyNameEnumerator))
        testData->outBufferLen = operation.params[1].tmpref.size;

    return result;
}

TEEC_Result Invoke_Malloc(TEEC_Session *session, uint32_t commandID, size_t inMemSize, ALL_MEMORY_HINTS inHint,
    uint32_t *origin)
{
    TEEC_Result result;
    TEEC_Operation operation = { 0 };

    // Invoke command
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = inMemSize;
    operation.params[0].value.b = inHint;

    result = TEEC_InvokeCommand(session, commandID, &operation, origin);
    return result;
}
