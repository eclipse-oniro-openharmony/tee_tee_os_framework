/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2019. All rights reserved.
 * Description: keymaster command authentication header
 * Create: 2015-01-17
 */
#ifndef __KM_CMD_AUTH_H
#define __KM_CMD_AUTH_H

#include "tee_internal_api.h"
#include "keymaster_defs.h"
#include "km_types.h"

typedef TEE_Result (*km_func)(uint32_t param_types, TEE_Param params[PARAM_COUNT]);
typedef TEE_Result (*km_func_const)(uint32_t param_types, const TEE_Param params[PARAM_COUNT]);
struct cmd_invoke {
    enum SVC_KEYMASTER_CMD_ID cmd;
    km_func func;
};

struct cmd_invok_const {
    enum SVC_KEYMASTER_CMD_ID cmd;
    km_func_const func_const;
};

struct ca_white_name_t {
    const char name[MAX_FILE_NAME_LEN];
    const uint32_t uid;
};

TEE_Result ta_cmd_check(const void *session_context, uint32_t cmd_id);
TEE_Result add_caller(void);
int32_t ta_access_check(uint32_t cmd_id);
TEE_Result handle_cmd_id(uint32_t cmd_id, uint32_t param_types, TEE_Param params[PARAM_COUNT]);
#endif
