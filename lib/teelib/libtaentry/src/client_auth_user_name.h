/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: client auth func statement for ta
 * Create: 2022-03-29
 */
#ifndef CLIENT_AUTH_USER_NAME_H
#define CLIENT_AUTH_USER_NAME_H

#include <stdint.h>
#include <tee_defines.h>
#include "client_auth_pub_interfaces.h"

struct ca_exec_info {
    char *pkg_name;
    char *user_name;
    uint32_t pkg_name_len;
    uint32_t user_name_len;
};

/* Keep tee_caller_info and tee_caller_info compatible */
struct tee_caller_info {
    uint32_t caller_type;
    union {
        TEE_UUID ta_uuid;
        struct ca_exec_info ca_exec;
    } caller;
    struct dlist_node list;
};

TEE_Result get_caller_candinfo(
    struct tee_caller_info *cand, const TEE_Param params[TA_COMMAND_TEE_PARAM_NUM], char *sig_buf);

TEE_Result check_perm(
    const struct tee_caller_info *allowed_caller, const struct tee_caller_info *candidate, bool *flag);

struct tee_caller_info *get_global_tee_caller_info(void);

#endif