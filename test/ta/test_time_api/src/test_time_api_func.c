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
#include <securec.h>
#include <tee_time_api.h>
#include <tee_trusted_storage_api.h>
#include "test_time_api_func.h"

static TEE_Result TestGetSystemTime(TEE_Param params[4])
{
    tlogi("[%s] begin:", __FUNCTION__);

    TEE_Time time = {0};
    TEE_GetSystemTime(&time);
    params[1].value.a = time.seconds;
    tlogi("GetSystemTime: %ds %dms", time.seconds, time.millis);
    return TEE_SUCCESS;
}

static TEE_Result CheckTimeInterval(uint64_t startTime, uint64_t endTime, uint32_t waitTime)
{
    if (endTime == startTime) {
        tloge("endTime (%llu) == startTime (%llu)\n", endTime, startTime);
        return TEE_ERROR_GENERIC;
    }

    if ((endTime - startTime) < (uint64_t)waitTime) {
        uint64_t subTime = endTime - startTime;
        tloge("(endTime (%llu) - startTime (%llu) = subTime(%llu)) < waitTime (%u)\n",
            endTime, startTime, subTime, waitTime);
        return TEE_ERROR_GENERIC;
    }

    if ((endTime - startTime - waitTime) > (uint64_t)(waitTime / 10)) { /* 误差10%以内可接受 */
        tloge("(endTime (%llu) - startTime (%llu)) > (waitTime (%u) + TEE_TEST_TIMER_BASE), "
            "and over 10\% tolerance\n", endTime, startTime, waitTime);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result TestTEEWait()
{
    tlogi("[%s] begin:", __FUNCTION__);

    TEE_Time startTime, endTime;
    const uint32_t waitTime = 5000;
    TEE_GetSystemTime(&startTime);
    tlogi("begin wait %ums", waitTime);
    TEE_Result ret = TEE_Wait(waitTime);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_Wait fail, ret = 0x%x", ret);
        return ret;
    }
    TEE_GetSystemTime(&endTime);

    uint64_t startTimeWithMs = startTime.seconds * MILLISECOND + startTime.millis;
    uint64_t endTimeWithMs = endTime.seconds * MILLISECOND + endTime.millis;
    ret = CheckTimeInterval(startTimeWithMs, endTimeWithMs, waitTime);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_Wait check time interval fail.");
    }

    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}

static void RemovePersistentTimeFile(void)
{
    TEE_ObjectHandle object = NULL;
    TEE_Result ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, PERSISTENT_TIME_BASE_FILE,
        strlen(PERSISTENT_TIME_BASE_FILE), TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META, &object);
    if (ret == TEE_SUCCESS) {
        tlogi("persistent time file is exist\n");
        TEE_CloseAndDeletePersistentObject(object);
        tlogi("fremove time file\n");
    } else {
        tlogi("persistent time file is not exist!\n");
    }
}

static TEE_Result TestGetPersistentTime()
{
    tlogi("[%s] begin:", __FUNCTION__);
    TEE_Time time;
    TEE_Result ret = TEE_GetTAPersistentTime(&time);
    tlogi("first time to get persistent time, not check. ret = 0x%x, seconds = %u, millis = %u",
        ret, time.seconds, time.millis);

    RemovePersistentTimeFile();
    ret = TEE_GetTAPersistentTime(&time);
    if (ret != TEE_ERROR_TIME_NOT_SET) {
        tloge("GetTAPersistentTime fail after remove persistent time file; before set time. ret = 0x%x", ret);
        return TEE_ERROR_GENERIC;
    }

    const uint32_t reserved10S = 10;
    const uint32_t wait5S = 5;
    TEE_Time setTime = {
        .seconds = UINT32_MAX - reserved10S,
        .millis = 0,
    };
    ret = TEE_SetTAPersistentTime(&setTime);
    if (ret != TEE_SUCCESS) {
        tloge("set time fail ret = 0x%x", ret);
        return TEE_ERROR_GENERIC;
    }

    TEE_Wait(MILLISECOND * wait5S);
    ret = TEE_GetTAPersistentTime(&time);
    if (ret != TEE_SUCCESS || time.seconds > UINT32_MAX - reserved10S + wait5S + 1 ||
        time.seconds < UINT32_MAX - reserved10S + wait5S - 1) {
        tloge("get time fail. ret = 0x%x, get time is %ds %dms", ret, time.seconds, time.millis);
        return TEE_ERROR_GENERIC;
    }

    TEE_Wait(MILLISECOND * reserved10S); // get time is UINT32_MAX - 10s + 5s + 10s > UINT32_MAX; get time is 5s
    ret = TEE_GetTAPersistentTime(&time);
    if (ret != TEE_ERROR_OVERFLOW || time.seconds > wait5S + 1 || time.seconds < wait5S - 1) {
        tloge("get time for overflow fail, ret = 0x%x, get time is %ds, %dms", ret, time.seconds, time.millis);
        return TEE_ERROR_GENERIC;
    }

    tlogi("[%s] end.", __FUNCTION__);
    return TEE_SUCCESS;
}

static TEE_Result TestSetPersistentTime()
{
    tlogi("[%s] begin:", __FUNCTION__);
    RemovePersistentTimeFile();
    const uint32_t reserved10S = 10;
    const uint32_t wait5S = 5;
    TEE_Time setTime = {
        .seconds = reserved10S,
        .millis = 0,
    };
    TEE_Result ret = TEE_SetTAPersistentTime(&setTime);
    if (ret != TEE_SUCCESS) {
        tloge("set time fail ret = 0x%x", ret);
        return TEE_ERROR_GENERIC;
    }

    TEE_Time getTime = {0};
    ret = TEE_GetTAPersistentTime(&getTime);
    if (ret != TEE_SUCCESS || (getTime.seconds != reserved10S && getTime.seconds != reserved10S + 1)) {
        tloge("get time fail. ret = 0x%x, get time is %ds %dms", ret, getTime.seconds, getTime.millis);
        return TEE_ERROR_GENERIC;
    }

    tlogi("begin wait %us", wait5S);
    TEE_Wait(MILLISECOND * wait5S);
    setTime.seconds = reserved10S;
    ret = TEE_SetTAPersistentTime(&setTime);
    if (ret != TEE_SUCCESS) {
        tloge("set time fail ret = 0x%x", ret);
        return TEE_ERROR_GENERIC;
    }

    (void)memset_s(&getTime, sizeof(getTime), 0, sizeof(getTime));
    ret = TEE_GetTAPersistentTime(&getTime);
    if (ret != TEE_SUCCESS || (getTime.seconds != reserved10S && getTime.seconds != reserved10S + 1)) {
        tloge("get time fail. ret = 0x%x, get time is %ds %dms", ret, getTime.seconds, getTime.millis);
        return TEE_ERROR_GENERIC;
    }

    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}

static TEE_Result TestGetREETime(TEE_Param params[4])
{
    tlogi("[%s] begin:", __FUNCTION__);

    TEE_Time time = {0};
    TEE_GetREETime(&time);
    params[1].value.a = time.seconds;
    tlogi("GetREETime: %ds %dms", time.seconds, time.millis);
    return TEE_SUCCESS;
}

TEE_Result TestTimeApi(uint32_t cmdId, TEE_Param params[4])
{
    tlogi("%s begin: cmdId is %d.", __FUNCTION__, cmdId);
    TEE_Result ret = TEE_SUCCESS;

    switch (cmdId) {
        case CMD_ID_TEST_GET_SYSTEM_TIME:
            ret = TestGetSystemTime(params);
            break;
        case CMD_ID_TEST_TEE_WAIT:
            ret = TestTEEWait();
            break;
        case CMD_ID_TEST_GET_PERSISTENT_TIME:
            ret = TestGetPersistentTime();
            break;
        case CMD_ID_TEST_SET_PERSISTENT_TIME:
            ret = TestSetPersistentTime();
            break;
        case CMD_ID_TEST_GET_REE_TIME:
            ret = TestGetREETime(params);
            break;
        default:
            tlogi("unknown command id, cmdId: %u\n", cmdId);
            return TEE_ERROR_INVALID_CMD;
    }

    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}