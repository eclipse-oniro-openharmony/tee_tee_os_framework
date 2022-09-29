/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:lBRwzWIfWflpkuvEPG9oHU2mxP0IzvCfvv+i+/xvfe6PT8VRR+8jz7b5YQbqzI49/C6xSBgi
2fFxGZUs+G3nkUIkBkfRerjPcgJTCLqrXspNkFCGTLklL/GZHRhiXBwGnNKhh0MAXEOVfrQU
iukZUWJ4vidruSf/U7e9gpUyQAooCWCSaeb3aIYEst5WD1qne8GcO+5QGB0g7/S8T09ixUGT
nR+osDAHaIEfyoPHfIFAJAQLD0ohh2OwUozrcXB/#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: client auth func definition for ta
 * Author: yangjing y00416812
 * Create: 2020-02-15
 */

#include "client_auth.h"
#include <string.h>
#include <securec.h>
#include <tee_ext_api.h>
#include <tee_log.h>
#include "elf_main_entry.h"
#include "client_auth_uid.h"

static bool is_invalid_param_type(uint32_t param_types, const TEE_Param params[TA_COMMAND_TEE_PARAM_NUM])
{
    bool param_check =
        (params == NULL) || (TEE_PARAM_TYPE_GET(param_types, CA_PARAM_CERT_INDEX) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (TEE_PARAM_TYPE_GET(param_types, CA_PARAM_PKG_NAME_INDEX) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (params[CA_PARAM_CERT_INDEX].memref.buffer == NULL) || (params[CA_PARAM_CERT_INDEX].memref.size == 0) ||
        (params[CA_PARAM_PKG_NAME_INDEX].memref.buffer == NULL) || (params[CA_PARAM_PKG_NAME_INDEX].memref.size == 0);
    return param_check;
}

static TEE_Result get_candinfo(
    uint32_t param_types, const TEE_Param params[TA_COMMAND_TEE_PARAM_NUM], struct tee_caller_info *cand)
{
    char *sig_buf = NULL;
    const uint32_t max_pkgname_len = get_max_pkgname_len();

    if (cand == NULL) {
        tloge("cand in Null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* whether caller is from CA or TA */
    cand->caller_type = tee_get_session_type();
    if (cand->caller_type == CALLER_TYPE_CA) {
        /* For CA, 1. Check Params TYPE */
        if (is_invalid_param_type(param_types, params)) {
            tloge("Bad expected parameter types\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }

        /* 2. get CA's cert info: package_name, uid or signature */
        sig_buf = params[CA_PARAM_CERT_INDEX].memref.buffer;

        /* 3. check pkg name buffer's size */
        if (params[CA_PARAM_PKG_NAME_INDEX].memref.size > max_pkgname_len) {
            tloge("Bad expected parameter buffer size\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
        cand->caller_type |= CALLER_CA_NAME;
        cand->caller.ca_exec.pkg_name     = params[CA_PARAM_PKG_NAME_INDEX].memref.buffer;
        cand->caller.ca_exec.pkg_name_len = strnlen(params[CA_PARAM_PKG_NAME_INDEX].memref.buffer,
            params[CA_PARAM_PKG_NAME_INDEX].memref.size);
        TEE_Result res = get_caller_candinfo(cand, params, sig_buf);
        if (res != TEE_SUCCESS)
            return res;
    } else if (cand->caller_type == CALLER_TYPE_TA) {
        /*
         * Do nothing here.
         * TA need to check uuid itself,
         * get uuid through func: tee_ext_get_caller_info.
         */
    } else {
        tloge("unkown client type\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result add_caller_ta(struct dlist_node *allowed_caller_list_head, uint32_t *caller_num)
{
    struct tee_caller_info *item = NULL;
    const uint32_t max_allowed_caller = get_max_allowed_caller();

    if (allowed_caller_list_head == NULL) {
        tloge("allowed_caller_list_head is NULL\n");
        return TEE_ERROR_GENERIC;
    }
    if (*caller_num >= max_allowed_caller) {
        tloge("Too many allowed callers, MAX AllowedCaller is %u\n", max_allowed_caller);
        return TEE_ERROR_GENERIC;
    }

    if (is_create_entry_processed()) {
        tloge("Not allowed to add caller after create entry\n");
        return TEE_ERROR_GENERIC;
    }

    /* item will only be freed when ta proc exit */
    item = TEE_Malloc(sizeof(*item), 0);
    if (item == NULL) {
        tloge("caller malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    item->caller_type = CALLER_TYPE_TA | CALLER_TA_ALL;
    dlist_insert_tail(&(item->list), allowed_caller_list_head);
    (*caller_num)++;

    return TEE_SUCCESS;
}

TEE_Result AddCaller_TA_all(void)
{
    tlogd("teelib add ta all\n");
    struct dlist_node *allowed_caller_list_head = get_allowed_caller_list_head();
    uint32_t *allowed_caller_num = get_global_caller_num();
    return add_caller_ta(allowed_caller_list_head, allowed_caller_num);
}

static bool check_caller_type(const struct tee_caller_info *allowed_caller, const struct tee_caller_info *candidate)
{
    return ((allowed_caller->caller_type == (CALLER_TYPE_TA | CALLER_TA_ALL)) &&
            (candidate->caller_type == CALLER_TYPE_TA));
}

static TEE_Result check_candidate_perm(
    const struct dlist_node *allowed_caller_list_head, const struct tee_caller_info *candidate)
{
    bool flag = false;
    struct dlist_node *pos = NULL;

    dlist_for_each(pos, allowed_caller_list_head) {
        struct tee_caller_info *allowed_caller = dlist_entry(pos, struct tee_caller_info, list);
        flag = check_caller_type(allowed_caller, candidate);
        if (flag) {
            tlogd("TA is checked OK\n");
            return TEE_SUCCESS;
        }

        if (candidate->caller_type != allowed_caller->caller_type)
            continue;
        TEE_Result res = check_perm(allowed_caller, candidate, &flag);
        if (res != TEE_SUCCESS)
            return res;
        if (flag) {
            tlogd("CA checked OK\n");
            return TEE_SUCCESS;
        }
    }
    tloge("caller has no permission\n");

    return TEE_ERROR_ACCESS_DENIED;
}

static struct dlist_node *get_caller_info(void)
{
    struct dlist_node *allowed_caller_list_head = get_allowed_caller_list_head();
    uint32_t *allowed_caller_num = get_global_caller_num();
    if (dlist_empty(allowed_caller_list_head) || (*allowed_caller_num == 0)) {
        tloge("allowed caller invalid\n");
        return NULL;
    }

    return allowed_caller_list_head;
}

TEE_Result check_client_perm(uint32_t param_types, const TEE_Param params[TA_COMMAND_TEE_PARAM_NUM])
{
    int32_t sret;
    struct dlist_node *allowed_caller = NULL;

    /* when caller is not CA, param can be null */
    allowed_caller = get_caller_info();
    if (allowed_caller == NULL) {
        tloge("no caller is allowed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct tee_caller_info candidate;
    sret = memset_s(&candidate, sizeof(candidate), 0x00, sizeof(candidate));
    if (sret != EOK) {
        tloge("client perm clear candidate fail sret=%d\n", sret);
        return TEE_ERROR_GENERIC;
    }

    if (get_candinfo(param_types, params, &candidate) != TEE_SUCCESS) {
        tloge("Get caller info failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return check_candidate_perm(allowed_caller, &candidate);
}

/*
 * A stub function is added to ensure code normalization on multiple platforms
 */
TEE_Result TEE_EXT_CheckClientPerm(uint32_t param_types, const TEE_Param params[TA_COMMAND_TEE_PARAM_NUM])
{
    tlogd("Check CA params\n");
    (void)param_types;
    (void)params;
    return TEE_SUCCESS;
}
