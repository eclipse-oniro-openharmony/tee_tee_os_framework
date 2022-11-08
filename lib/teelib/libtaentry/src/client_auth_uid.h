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
#ifndef CLIENT_AUTH_UID_H
#define CLIENT_AUTH_UID_H
#include "client_auth_pub_interfaces.h"

struct ca_exec_info {
    char *pkg_name;
    uint32_t pkg_name_len;
    uint32_t uid;
};

struct ca_apk_info {
    char *pkg_name;
    char *modulus;
    char *pub_exponent;
    uint32_t pkg_name_len;
    uint32_t modulus_len;
    uint32_t pub_exp_len;
};

#define RESERVED_SIZE 32

/* Keep tee_caller_info and tee_caller_info compatible */
struct tee_caller_info {
    uint32_t caller_type;
    union {
        TEE_UUID ta_uuid;
        struct ca_exec_info ca_exec;
        struct ca_apk_info ca_apk;
    } caller;
    struct dlist_node list;
};

/* max size is big enough for RSA-8192 */
#define SIG_BUF_MAX_SIZE 20000

#define HEX_PER_BYTE 2

TEE_Result get_caller_candinfo(
    struct tee_caller_info *cand, const TEE_Param params[TA_COMMAND_TEE_PARAM_NUM], char *sig_buf);

TEE_Result check_perm(
    const struct tee_caller_info *allowed_caller, const struct tee_caller_info *candidate, bool *flag);

struct tee_caller_info *get_global_tee_caller_info();

#endif
