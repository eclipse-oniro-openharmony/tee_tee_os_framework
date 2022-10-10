/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: client auth func statement for ta
 * Create: 2022-03-29
 */
#ifndef CLIENT_AUTH_PUB_INTERFACES_H
#define CLIENT_AUTH_PUB_INTERFACES_H

#include <stdint.h>
#include <tee_defines.h>
#include <dlist.h>
#ifdef CONFIG_TEST_CA_CHECK
#include "tee_test_calist.h"
#endif

#define TA_COMMAND_TEE_PARAM_NUM 4
#define CA_PARAM_CERT_INDEX 2
#define CA_PARAM_USR_NAME_INDEX 2
#define CA_PARAM_PKG_NAME_INDEX 3
#define RESERVED_SIZE 32

#define INIT_VAL 1U

enum caller_session_type {
    CALLER_TYPE_CA = 0x00U,
    CALLER_TYPE_TA = 0x01U,

    CALLER_CA_NAME = 0x10U,
    CALLER_CA_UID = 0x20U,
    CALLER_CA_SIGN = 0x40U,

    CALLER_TA_ALL = 0x100U, /* no striction for ta */
};

uint32_t *get_global_caller_num(void);

uint32_t get_max_allowed_caller(void);

uint32_t get_max_pkgname_len(void);

struct dlist_node *get_allowed_caller_list_head(void);

TEE_Result addcaller_ca_exec_check(const char *ca_name, uint32_t caller_num);

bool is_invalid_param(const TEE_Param params[TA_COMMAND_TEE_PARAM_NUM], const uint32_t max_pkgname_len);

#endif