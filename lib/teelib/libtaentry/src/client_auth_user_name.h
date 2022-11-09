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