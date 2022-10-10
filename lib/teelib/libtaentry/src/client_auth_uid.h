/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: client auth func statement for ta
 * Create: 2022-03-29
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
