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

#include <public_test.h>
#include <test_log.h>
#include <securec.h>
#include <common_test.h>

#include <session_mgr/client_session_mgr.h>

/**
 * @testcase.name      : GetSystemTime
 * @testcase.desc      : test TEE_GetSystemTime api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, TEE_GetSystemTime, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = {0};
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_GET_SYSTEM_TIME, operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    uint32_t time1 = operation.params[1].value.a;

    sleep(3); // wait for 3s
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_GET_SYSTEM_TIME, operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    uint32_t time2 = operation.params[1].value.a;
    ASSERT_LT(time1, time2);
    sess.Destroy();
}

/**
 * @testcase.name      : TeeWait
 * @testcase.desc      : test TEE_Wait api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, TeeWait, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_TEE_WAIT, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : GetPersistentTime
 * @testcase.desc      : test get persistent time
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, GetPersistentTime, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_GET_PERSISTENT_TIME, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : SetPersistentTime
 * @testcase.desc      : test set persistent time
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, SetPersistentTime, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_SET_PERSISTENT_TIME, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : GetReeTime
 * @testcase.desc      : test TEE_GetREETime api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, GetReeTime, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = ARITHMETIC_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = {0};
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_GET_REE_TIME, operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    uint32_t time1 = operation.params[1].value.a;

    sleep(3); // wait for 3s
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_GET_REE_TIME, operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    uint32_t time2 = operation.params[1].value.a;
    ASSERT_LT(time1, time2);
    sess.Destroy();
}
