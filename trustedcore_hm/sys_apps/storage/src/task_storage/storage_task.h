/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: storage task implementation
 * Create: 2018-05-18
 */
#ifndef __STORAGE_TASK_H
#define __STORAGE_TASK_H

#include <tee_defines.h>

#define PARAM_COUNT 4
TEE_Result TA_CreateEntryPoint(void);
void TA_DestroyEntryPoint(void);
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[PARAM_COUNT], void **sessionContext);
void TA_CloseSessionEntryPoint(void *session_context);
TEE_Result TA_InvokeCommandEntryPoint(void *session_context,
    uint32_t cmd_id, uint32_t paramTypes, TEE_Param params[PARAM_COUNT]);

#endif
