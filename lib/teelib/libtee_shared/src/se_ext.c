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

#include "hmdrv.h"
#include <sre_syscalls_id.h>
#include <string.h>
#include "tee_defines.h"
#include "tee_core_api.h"
#include "tee_log.h"

#define TEE_SERVICE_SEM                                    \
    {                                                      \
        0xaaa862d1, 0x22fe, 0x4609,                        \
        {                                                  \
            0xa4, 0xee, 0x86, 0x67, 0xf6, 0x53, 0x8f, 0x18 \
        }                                                  \
    }

#define CMD_SE_ESE_TRANSMIT 0x00000008
#define CMD_SE_ESE_READ     0x00000009
#define PARAMS_NUM          4
static TEE_TASessionHandle g_sem_session;

static int open_sem_session(TEE_TASessionHandle *session)
{
    TEE_Result ret;
    TEE_UUID uuid = TEE_SERVICE_SEM;
    TEE_Param params[PARAMS_NUM];
    uint32_t param_types;
    uint32_t return_origin = 0;

    if (session == NULL)
        return -1;

    param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    ret = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, param_types, params, session, &return_origin);
    if (ret != TEE_SUCCESS)
        tloge("Open TA Session FAIL, ret = %x, origin = %x", ret, return_origin);

    return ret;
}

static void close_sem_session(TEE_TASessionHandle session)
{
    TEE_CloseTASession(session);
    tlogd("Close TA Session");
}

int tee_ese_transmit(unsigned char *data, unsigned int size)
{
    uint32_t param_types;
    uint32_t return_origin = 0;
    TEE_Result ret;
    TEE_Param params[PARAMS_NUM];
    int rc;

    rc = open_sem_session(&g_sem_session);
    if (rc) {
        tloge("ese Open TA Session FAIL, ret=%d\n", rc);
        return rc;
    }

    params[0].memref.buffer = (void *)data;
    params[0].memref.size   = size;

    param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    ret = TEE_InvokeTACommand(g_sem_session, TEE_TIMEOUT_INFINITE, CMD_SE_ESE_TRANSMIT, param_types, params,
                              &return_origin);
    if (ret != TEE_SUCCESS)
        tloge("tee ese transmit ret = %x, origin = %x\n", ret, return_origin);

    close_sem_session(g_sem_session);
    return ret;
}

int tee_ese_read(unsigned int *data, unsigned int size)
{
    uint32_t param_types;
    uint32_t return_origin = 0;
    TEE_Result ret;
    TEE_Param params[PARAMS_NUM];
    int rc;

    rc = open_sem_session(&g_sem_session);
    if (rc) {
        tloge("ese Open TA Session FAIL, ret=%d\n", rc);
        return rc;
    }

    params[0].memref.buffer = (void *)data;
    params[0].memref.size   = size;

    param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    ret =
        TEE_InvokeTACommand(g_sem_session, TEE_TIMEOUT_INFINITE, CMD_SE_ESE_READ, param_types, params, &return_origin);
    if (ret != TEE_SUCCESS)
        tloge("tee ese read ret = %x, origin = %x\n", ret, return_origin);

    close_sem_session(g_sem_session);
    return ret;
}
