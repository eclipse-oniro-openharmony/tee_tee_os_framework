/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:lBRwzWIfWflpkuvEPG9oHU2mxP0IzvCfvv+i+/xvfe6PT8VRR+8jz7b5YQbqzI49/C6xSBgi
2fFxGZUs+G3nkUIkBkfRerjPcgJTCLqrXspNkFCGTLklL/GZHRhiXBwGnNKhh0MAXEOVfrQU
iukZUWJ4vidruSf/U7e9gpUyQAooCWCSaeb3aIYEst5WD1qne8GcO+5QGB0g7/S8T09ixUGT
nR+osDAHaIEfyoPHfIFAJAQLD0ohh2OwUozrcXB/#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: client auth function for kunpeng
 * Author: luozhengyi l00575763
 * Create: 2022-03-29
 */

#include "client_auth_user_name.h"
#include <string.h>
#include <securec.h>
#include <tee_ext_api.h>
#include <tee_log.h>

const uint32_t g_max_username_len = 256;

static TEE_Result addcaller_ca_exec_check_user(const char *ca_name, const char *user_name, uint32_t caller_num)
{
    TEE_Result res = addcaller_ca_exec_check(ca_name, caller_num);
    if (res != TEE_SUCCESS)
        return res;
    bool valid_user_name =
        (user_name == NULL) || ((uint32_t)strnlen(user_name, g_max_username_len) == g_max_username_len);
    if (valid_user_name) {
        tloge("Bad expected parameter user name\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static void ca_info_mem_free(struct tee_caller_info *item)
{
    if (item == NULL)
        return;
    if (item->caller.ca_exec.pkg_name != NULL) {
        TEE_Free(item->caller.ca_exec.pkg_name);
        item->caller.ca_exec.pkg_name = NULL;
    }
    if (item->caller.ca_exec.user_name != NULL) {
        TEE_Free(item->caller.ca_exec.user_name);
        item->caller.ca_exec.user_name = NULL;
    }
    TEE_Free(item);
}

/*
 * ca_name, user_name, item already checked in add_ca_exec
 * if error occurs, memory allocated here will be free by add_ca_exec
 */
static TEE_Result copy_caller_info(const char *ca_name, const char *user_name, struct tee_caller_info *item)
{
    int32_t sret;

    item->caller.ca_exec.pkg_name = TEE_Malloc((strlen(ca_name) + 1), 0);
    if (item->caller.ca_exec.pkg_name == NULL) {
        tloge("pkg name alloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    sret = memcpy_s(item->caller.ca_exec.pkg_name, strlen(ca_name) + 1, ca_name, strlen(ca_name));
    if (sret != EOK) {
        tloge("AddCaller exec copy pkg name fail sret=%d\n", sret);
        return TEE_ERROR_GENERIC;
    }

    item->caller.ca_exec.user_name = TEE_Malloc((strlen(user_name) + 1), 0);
    if (item->caller.ca_exec.user_name == NULL) {
        tloge("user name alloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    sret = memcpy_s(item->caller.ca_exec.user_name, strlen(user_name) + 1, user_name, strlen(user_name));
    if (sret != EOK) {
        tloge("AddCaller exec copy user name fail sret=%d\n", sret);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result add_ca_exec(const char *ca_name, const char *user_name)
{
    TEE_Result ret;
    struct tee_caller_info *item = NULL;
    struct dlist_node *allowed_caller_list_head = get_allowed_caller_list_head();
    uint32_t *caller_num = get_global_caller_num();

    if (allowed_caller_list_head == NULL) {
        tloge("allowed_caller_list_head is NULL\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    ret = addcaller_ca_exec_check_user(ca_name, user_name, *caller_num);
    if (ret != TEE_SUCCESS)
        return ret;

    item = TEE_Malloc(sizeof(*item), 0);
    if (item == NULL) {
        tloge("addcaller alloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    item->caller_type = CALLER_TYPE_CA | CALLER_CA_NAME | CALLER_CA_SIGN;
    item->caller.ca_exec.pkg_name = NULL;
    item->caller.ca_exec.user_name = NULL;

    ret = copy_caller_info(ca_name, user_name, item);
    if (ret != TEE_SUCCESS) {
        tloge("copy caller info failed\n");
        ca_info_mem_free(item);
        item = NULL;
        return ret;
    }
    dlist_insert_tail(&(item->list), allowed_caller_list_head);
    (*caller_num)++;

    return TEE_SUCCESS;
}

TEE_Result addcaller_ca_exec(const char *ca_name, const char *user_name)
{
    tlogd("teelib add ca exec\n");
    return add_ca_exec(ca_name, user_name);
}

static bool check_cloud_ca(const struct ca_exec_info *cand_exec, const struct ca_exec_info *allowed_exec)
{
    return ((cand_exec->pkg_name_len == strlen(allowed_exec->pkg_name)) &&
            (!TEE_MemCompare(cand_exec->pkg_name, allowed_exec->pkg_name, strlen(allowed_exec->pkg_name))) &&
            (cand_exec->user_name_len == strlen(allowed_exec->user_name)) &&
            (!TEE_MemCompare(cand_exec->user_name, allowed_exec->user_name, strlen(allowed_exec->user_name))));
}

TEE_Result get_caller_candinfo(
    struct tee_caller_info *cand, const TEE_Param params[TA_COMMAND_TEE_PARAM_NUM], char *sig_buf)
{
    const uint32_t max_pkgname_len = get_max_pkgname_len();

    if (cand == NULL) {
        tloge("cand is Null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool flag = is_invalid_param(params, max_pkgname_len);
    if (flag == true) {
        tloge("params is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* we verify CA's package name and user name at kunpeng platform */
    cand->caller_type |= CALLER_CA_SIGN;
    if (params[CA_PARAM_USR_NAME_INDEX].memref.size > g_max_username_len) {
        tloge("Bad expected parameter buffer size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    cand->caller.ca_exec.user_name = sig_buf;
    cand->caller.ca_exec.user_name_len =
        strnlen(params[CA_PARAM_USR_NAME_INDEX].memref.buffer, params[CA_PARAM_USR_NAME_INDEX].memref.size);

    return TEE_SUCCESS;
}

TEE_Result check_perm(const struct tee_caller_info *allowed_caller, const struct tee_caller_info *candidate, bool *flag)
{
    const struct ca_exec_info *cand_exec = NULL;
    const struct ca_exec_info *allowed_exec = NULL;

    if (allowed_caller == NULL) {
        tloge("no caller is allowed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (candidate == NULL) {
        tloge("candidate is NULL\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    switch (candidate->caller_type) {
    case (CALLER_TYPE_CA | CALLER_CA_NAME | CALLER_CA_SIGN):
        cand_exec = &(candidate->caller.ca_exec);
        allowed_exec = &(allowed_caller->caller.ca_exec);
        (*flag) = check_cloud_ca(cand_exec, allowed_exec);
        break;
    default:
        tloge("caller's type is not supported\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}