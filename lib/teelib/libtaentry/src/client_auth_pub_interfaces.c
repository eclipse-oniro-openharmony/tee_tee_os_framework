/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:lBRwzWIfWflpkuvEPG9oHU2mxP0IzvCfvv+i+/xvfe6PT8VRR+8jz7b5YQbqzI49/C6xSBgi
2fFxGZUs+G3nkUIkBkfRerjPcgJTCLqrXspNkFCGTLklL/GZHRhiXBwGnNKhh0MAXEOVfrQU
iukZUWJ4vidruSf/U7e9gpUyQAooCWCSaeb3aIYEst5WD1qne8GcO+5QGB0g7/S8T09ixUGT
nR+osDAHaIEfyoPHfIFAJAQLD0ohh2OwUozrcXB/#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: client auth function for Public
 * Author: luozhengyi l00575763
 * Create: 2022-03-29
 */
#include "client_auth_pub_interfaces.h"
#include <string.h>
#include <securec.h>
#include <tee_log.h>
#include <tee_ext_api.h>
#include "elf_main_entry.h"

static const uint32_t g_max_pkgname_len = 256;

static uint32_t g_allowed_caller_num = 0;
static const uint32_t g_max_allowed_caller = 16;
static struct dlist_node g_allowed_caller_list_head = dlist_head_init(g_allowed_caller_list_head);

struct dlist_node *get_allowed_caller_list_head(void)
{
    return &g_allowed_caller_list_head;
}


uint32_t *get_global_caller_num(void)
{
    return &g_allowed_caller_num;
}

uint32_t get_max_allowed_caller(void)
{
    return g_max_allowed_caller;
}

uint32_t get_max_pkgname_len(void)
{
    return g_max_pkgname_len;
}

#ifdef CONFIG_TEST_CA_CHECK
static bool is_test_ca(const char *ca_name)
{
    const char **testca_list = get_testca_blacklist();
    const uint32_t testca_num = get_testca_blacklist_num();
    if (testca_list == NULL || testca_num == 0) {
        tlogd("testca_list is null\n");
        return false;
    }

    for (uint32_t i = 0; i < testca_num; i++) {
        if (testca_list[i] == NULL) {
            tlogd("get ca name failed\n");
            continue;
        }

        if (strstr(ca_name, testca_list[i]) != NULL)
            return true;
    }
    return false;
}
#endif

TEE_Result addcaller_ca_exec_check(const char *ca_name, uint32_t caller_num)
{
    const uint32_t max_allowed_caller = g_max_allowed_caller;
    const uint32_t max_pkgname_len = g_max_pkgname_len;

    if (caller_num >= max_allowed_caller) {
        tloge("Too many allowed callers, MAX AllowedCaller is %u\n", max_allowed_caller);
        return TEE_ERROR_GENERIC;
    }

    if (is_create_entry_processed()) {
        tloge("Not allowed to add caller after create entry\n");
        return TEE_ERROR_GENERIC;
    }

    /* len is smaller than max pkgname len - 1 */
    if ((ca_name == NULL) || ((uint32_t)strnlen(ca_name, max_pkgname_len) == max_pkgname_len)) {
        tloge("Bad expected parameter ca name\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
#ifdef CONFIG_TEST_CA_CHECK
    if (is_test_ca(ca_name)) {
        tloge("illegal input\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
#endif
    return TEE_SUCCESS;
}

bool is_invalid_param(const TEE_Param params[TA_COMMAND_TEE_PARAM_NUM], const uint32_t max_pkgname_len)
{
    bool param_check = (params == NULL) || (params[CA_PARAM_CERT_INDEX].memref.buffer == NULL) ||
                       (params[CA_PARAM_CERT_INDEX].memref.size == 0) ||
                       (params[CA_PARAM_PKG_NAME_INDEX].memref.buffer == NULL) ||
                       (params[CA_PARAM_PKG_NAME_INDEX].memref.size == 0) ||
                       (params[CA_PARAM_PKG_NAME_INDEX].memref.size > max_pkgname_len);
    return param_check;
}