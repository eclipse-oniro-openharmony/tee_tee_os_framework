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
#ifndef __TEST_TCF_CMDID_H__
#define __TEST_TCF_CMDID_H__

#include <base_cmdid.h>
#include <test_defines.h>

typedef enum {
    CMD_TEE_GetPropertyAsString = 0,
    CMD_TEE_GetPropertyAsBool,
    CMD_TEE_GetPropertyAsU32,
    CMD_TEE_GetPropertyAsU64,
    CMD_TEE_GetPropertyAsBinaryBlock,
    CMD_TEE_GetPropertyAsUUID,
    CMD_TEE_GetPropertyAsIdentity,
    CMD_TEE_AllocatePropertyEnumerator,
    CMD_TEE_FreePropertyEnumerator,
    CMD_TEE_StartPropertyEnumerator,
    CMD_TEE_ResetPropertyEnumerator,
    CMD_TEE_GetPropertyNameEnumerator,
    CMD_TEE_GetNextPropertyEnumerator,
    CMD_TEE_Malloc,
    CMD_TEE_Realloc,
    CMD_TEE_MemMove,
    CMD_TEE_MemCompare,
    CMD_TEE_MemFill,
    CMD_TEE_Free,
} TCFCmdId;

#define GET_TCF_CMDID(inner) GET_CMD_ID(BASEID_TCF, inner)

#define INPUTBUFFER_ISNULL 1
#define OUTPUTBUFFER_ISNULL 2
#define OUTPUTBUFFERSIZE_ISNULL 3
#define OUTPUTBUFFERSIZE_ISZERO 4
#define OUTPUTBUFFERSIZE_TOOSHORT 5

#endif