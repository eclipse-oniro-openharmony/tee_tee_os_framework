/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:lBRwzWIfWflpkuvEPG9oHU2mxP0IzvCfvv+i+/xvfe6PT8VRR+8jz7b5YQbqzI49/C6xSBgi
2fFxGZUs+G3nkUIkBkfRerjPcgJTCLqrXspNkFCGTLklL/GZHRhiXBwGnNKhh0MAXEOVfrQU
iukZUWJ4vidruSf/U7e9gpUyQAooCWCSaeb3aIYEst5WD1qne8GcO+5QGB0g7/S8T09ixUGT
nR+osDAHaIEfyoPHfIFAJAQLD0ohh2OwUozrcXB/#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: client auth function for others feature except kunpeng
 * Author: luozhengyi l00575763
 * Create: 2022-03-29
 */
#include "client_auth_pub_interfaces.h"
#include "client_auth_uid.h"
#include <string.h>
#include <securec.h>
#include <tee_ext_api.h>
#include <tee_mem_mgmt_api.h>
#include <tee_log.h>
#include "elf_main_entry.h"

const uint32_t g_module_len_aligned_size = 256;
const uint32_t g_max_pub_exp_len = 512;

static const uint32_t g_max_modulus = 1024;

static TEE_Result check_len_param1(uint32_t sig_len, uint32_t max_len, uint32_t check_len)
{
    if ((sig_len > max_len) || (sig_len < check_len)) {
        tloge("Bad expected parameter1: sig len = %d, check len = %d\n", sig_len, check_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result check_len_param2(uint32_t sig_len, uint32_t check_len)
{
    if ((check_len >= sig_len) || (check_len <= (sizeof(int) + sizeof(int)))) {
        tloge("Bad expected parameter2: sig len = %d, check len = %d\n", sig_len, check_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static bool invalid_pub_exp_len(const struct tee_caller_info *cand)
{
    return ((cand->caller.ca_apk.pub_exp_len > g_max_pub_exp_len) || (cand->caller.ca_apk.pub_exp_len == 0));
}

static bool invalid_modulus_len(const struct tee_caller_info *cand)
{
    /* 1024bit is 128Byte, which is g_module_len_aligned_size/HEX_PER_BYTE */
    return ((cand->caller.ca_apk.modulus_len > g_max_modulus) || (cand->caller.ca_apk.modulus_len == 0));
}

static TEE_Result get_cand_sign_info(
    const TEE_Param params[TA_COMMAND_TEE_PARAM_NUM], struct tee_caller_info *cand, char *sig_buf)
{
    uint32_t sig_len;
    uint32_t check_len;
    TEE_Result res;
    uint32_t offset;

    /*
     * use max_len to prevent check_len overflow.
     * max_len > (2*sizeof(int) + modulus_len/x + pub_exp_len/y)
     * max_len is big enough for RSA-8192.
     */
    sig_len = params[CA_PARAM_CERT_INDEX].memref.size;
    /* get modulus_len */
    check_len = sizeof(int);
    res = check_len_param1(sig_len, SIG_BUF_MAX_SIZE, check_len);
    if (res != TEE_SUCCESS)
        return res;

    cand->caller_type |= CALLER_CA_NAME;
    cand->caller_type |= CALLER_CA_SIGN;
    cand->caller.ca_apk.pkg_name = params[CA_PARAM_PKG_NAME_INDEX].memref.buffer;
    cand->caller.ca_apk.pkg_name_len =
        strnlen(params[CA_PARAM_PKG_NAME_INDEX].memref.buffer, params[CA_PARAM_PKG_NAME_INDEX].memref.size);
    cand->caller.ca_apk.modulus_len = *((uint32_t *)sig_buf);
    if (invalid_modulus_len(cand)) {
        tloge("Bad expected parameter: modules/x len error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    check_len += cand->caller.ca_apk.modulus_len;
    check_len += sizeof(int);
    res = check_len_param2(sig_len, check_len);
    if (res != TEE_SUCCESS)
        return res;

    offset = sizeof(uint32_t);
    cand->caller.ca_apk.modulus = sig_buf + offset;

    offset += cand->caller.ca_apk.modulus_len;
    cand->caller.ca_apk.pub_exp_len = *((uint32_t *)(sig_buf + offset));
    if (invalid_pub_exp_len(cand)) {
        tloge("Bad expected parameter: params[2] pub exp/y len error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    check_len += cand->caller.ca_apk.pub_exp_len;
    if (check_len != sig_len) {
        tloge("Bad expected parameter3: sig len = %d, check len = %d\n", sig_len, check_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    offset += sizeof(uint32_t);
    cand->caller.ca_apk.pub_exponent = sig_buf + offset;

    return TEE_SUCCESS;
}

#define HEX_ALPHA_BASE 10

static uint8_t hex_to_byte(char c)
{
    if ((c >= '0') && (c <= '9'))
        return c - '0';
    else if ((c >= 'A') && (c <= 'F'))
        return c - 'A' + HEX_ALPHA_BASE;
    else if ((c >= 'a') && (c <= 'f'))
        return c - 'a' + HEX_ALPHA_BASE;
    else
        return 0;
}

/* when str len is odd number, add a character 0 at the beginning */
#define HEX_NUM_SHIFT 4
#define ODD_OFFSET 1

static TEE_Result str_to_byte(char *result, uint32_t result_sz, const char *str)
{
    uint8_t n1;
    uint8_t n2;
    size_t len;
    char *newstr = NULL;
    bool invalid_arg = ((result == NULL) || (str == NULL));
    bool is_odd = false;

    if (invalid_arg) {
        tloge("input is Null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* has checked '\0' for str before */
    len = strlen(str);
    if (result_sz < (uint32_t)(len / HEX_PER_BYTE)) {
        tloge("invalid size: result size: %u, len: %zu\n", result_sz, len);
        return TEE_ERROR_GENERIC;
    }

    if (len % HEX_PER_BYTE == 1) { /* judge odd num */
        len = len + ODD_OFFSET;
        is_odd = true;
    }

    newstr = TEE_Malloc(len, 0);
    if (newstr == NULL) {
        tloge("str Malloc Failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (is_odd) {
        newstr[0] = '0';
        if (memcpy_s(newstr + ODD_OFFSET, len - ODD_OFFSET, str, strlen(str)) != EOK) {
            tloge("elf str to byte copy fail\n");
            goto err_out;
        }
    } else {
        if (memcpy_s(newstr, len, str, strlen(str)) != EOK) {
            tloge("elf str to byte copy fail\n");
            goto err_out;
        }
    }

    for (size_t i = 0; i < len / HEX_PER_BYTE; i++) {
        n1 = hex_to_byte(newstr[HEX_PER_BYTE * i]);
        n2 = hex_to_byte(newstr[HEX_PER_BYTE * i + 1]); /* switch every two element */
        result[i] = (char)((n1 << HEX_NUM_SHIFT) | n2);
    }

    TEE_Free(newstr);
    return TEE_SUCCESS;

err_out:
    TEE_Free(newstr);
    return TEE_ERROR_GENERIC;
}

static TEE_Result add_ca_exec(const char *ca_name, uint32_t ca_uid)
{
    int32_t sret;
    TEE_Result ret;
    struct tee_caller_info *item = NULL;
    struct dlist_node *allowed_caller_list_head = get_allowed_caller_list_head();
    uint32_t *caller_num = get_global_caller_num();

    if (allowed_caller_list_head == NULL) {
        tloge("allowed_caller_list_head is NULL\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    ret = addcaller_ca_exec_check(ca_name, *caller_num);
    if (ret != TEE_SUCCESS)
        return ret;

    item = TEE_Malloc(sizeof(*item), 0);
    if (item == NULL) {
        tloge("addcaller alloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    item->caller_type = CALLER_TYPE_CA | CALLER_CA_NAME | CALLER_CA_UID;
    item->caller.ca_exec.pkg_name = TEE_Malloc((strlen(ca_name) + 1), 0); /* for '\0' */
    if (item->caller.ca_exec.pkg_name == NULL) {
        tloge("name alloc failed\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto free_item;
    }

    /* add 1 for '\0' */
    sret = memcpy_s(item->caller.ca_exec.pkg_name, strlen(ca_name) + 1, ca_name, strlen(ca_name));
    if (sret != EOK) {
        tloge("AddCaller exec copy name fail sret=%d\n", sret);
        ret = TEE_ERROR_GENERIC;
        goto free_pkgname;
    }

    item->caller.ca_exec.uid = ca_uid;
    dlist_insert_tail(&(item->list), allowed_caller_list_head);
    (*caller_num)++;

    return TEE_SUCCESS;

free_pkgname:
    TEE_Free(item->caller.ca_exec.pkg_name);
    item->caller.ca_exec.pkg_name = NULL;

free_item:
    TEE_Free(item);
    item = NULL;
    return ret;
}

TEE_Result AddCaller_CA_exec(const char *ca_name, uint32_t ca_uid)
{
    tlogd("teelib add ca exec\n");
    return add_ca_exec(ca_name, ca_uid);
}

static TEE_Result addcaller_ca_apk_ca_name(struct tee_caller_info *item, const char *ca_name)
{
    int32_t sret;

    item->caller.ca_apk.pkg_name = TEE_Malloc((strlen(ca_name) + 1), 0); /* for '\0' */
    if (item->caller.ca_apk.pkg_name == NULL) {
        tloge("apk name alloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY; /* caller do free */
    }

    sret = memcpy_s(item->caller.ca_apk.pkg_name, strlen(ca_name) + 1, ca_name, strlen(ca_name));
    if (sret != EOK) {
        tloge("apk name copy fail sret=%d\n", sret);
        return TEE_ERROR_GENERIC; /* caller do free */
    }

    return TEE_SUCCESS;
}

static TEE_Result addcaller_ca_apk_modules(struct tee_caller_info *item, const char *modulus)
{
    /*
     * modulus must be 1024bits ~ 4096bits (256-1024bytes & 256bytes aligned) key.
     * Warning:
     * strlen is only suitable for modulus and pub_exponent in string,
     * not in hex.  --in params, modulus is in hex.
     * add 1 to make sure len no bigger than  g_max_modulus
     */
    if ((uint32_t)strnlen(modulus, g_max_modulus + 1) == g_max_modulus + 1) {
        tloge("Bad expected parameter pubkey\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    item->caller.ca_apk.modulus_len = (strlen(modulus) + 1) / HEX_PER_BYTE; /* make len even */
    item->caller.ca_apk.modulus = TEE_Malloc(item->caller.ca_apk.modulus_len, 0);
    if (item->caller.ca_apk.modulus == NULL) {
        tloge("apk modulus failed\n");
        return TEE_ERROR_OUT_OF_MEMORY; /* caller do free */
    }

    if (str_to_byte(item->caller.ca_apk.modulus, item->caller.ca_apk.modulus_len, modulus) != TEE_SUCCESS) {
        tloge("str to byte failed\n");
        return TEE_ERROR_OUT_OF_MEMORY; /* caller do free */
    }

    return TEE_SUCCESS;
}

static TEE_Result addcaller_ca_apk_pub_exponent(struct tee_caller_info *item, const char *pub_exponent)
{
    /* add 1 to make sure len is no bigger than g_module_len_aligned_size */
    if ((uint32_t)strnlen(pub_exponent, g_max_pub_exp_len + 1) == (g_max_pub_exp_len + 1)) {
        tloge("Bad expected parameter pub exponent\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    item->caller.ca_apk.pub_exp_len = (strlen(pub_exponent) + 1) / HEX_PER_BYTE; /* make len even */
    item->caller.ca_apk.pub_exponent = TEE_Malloc(item->caller.ca_apk.pub_exp_len, 0);
    if (item->caller.ca_apk.pub_exponent == NULL) {
        tloge("apk pub exponent failed\n");
        return TEE_ERROR_OUT_OF_MEMORY; /* caller do free */
    }

    if (str_to_byte(item->caller.ca_apk.pub_exponent, item->caller.ca_apk.pub_exp_len, pub_exponent) != TEE_SUCCESS) {
        tloge("str to byte failed\n");
        return TEE_ERROR_OUT_OF_MEMORY; /* caller do free */
    }

    return TEE_SUCCESS;
}

static void free_caller_node(struct tee_caller_info *item)
{
    /* TEE_Free will check if buffer's pointer is NULL first. */
    TEE_Free(item->caller.ca_apk.pub_exponent);
    item->caller.ca_apk.pub_exponent = NULL;

    TEE_Free(item->caller.ca_apk.modulus);
    item->caller.ca_apk.modulus = NULL;

    TEE_Free(item->caller.ca_apk.pkg_name);
    item->caller.ca_apk.pkg_name = NULL;

    TEE_Free(item);
}

static TEE_Result add_ca_apk(const char *ca_name, const char *modulus, const char *pub_exponent)
{
    TEE_Result ret;
    struct dlist_node *allowed_caller_list_head = get_allowed_caller_list_head();
    uint32_t *caller_num = get_global_caller_num();
    const uint32_t max_allowed_caller = get_max_allowed_caller();
    const uint32_t max_pkgname_len = get_max_pkgname_len();

    bool invalid_arg = ((ca_name == NULL) || (modulus == NULL) || (pub_exponent == NULL) ||
                        ((uint32_t)strnlen(ca_name, max_pkgname_len) == max_pkgname_len));
    struct tee_caller_info *item = NULL;

    if (*caller_num >= max_allowed_caller) {
        tloge("Too many allowed callers, MAX AllowedCaller is %u\n", max_allowed_caller);
        return TEE_ERROR_GENERIC;
    }

    if (is_create_entry_processed()) {
        tloge("Not allowed to add caller after TA create entry\n");
        return TEE_ERROR_GENERIC;
    }

    if (invalid_arg) {
        tloge("Bad expected parameter\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    item = TEE_Malloc(sizeof(*item), 0);
    if (item == NULL) {
        tloge("caller alloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    item->caller_type = CALLER_TYPE_CA | CALLER_CA_NAME | CALLER_CA_SIGN;
    ret = addcaller_ca_apk_ca_name(item, ca_name);
    if (ret != TEE_SUCCESS)
        goto free_out;

    ret = addcaller_ca_apk_modules(item, modulus);
    if (ret != TEE_SUCCESS)
        goto free_out;

    ret = addcaller_ca_apk_pub_exponent(item, pub_exponent);
    if (ret != TEE_SUCCESS)
        goto free_out;

    dlist_insert_tail(&(item->list), allowed_caller_list_head);
    (*caller_num)++;
    return TEE_SUCCESS;

    tloge("AddCaller apk To List failed\n");

free_out:
    free_caller_node(item);
    return ret;
}

TEE_Result AddCaller_CA_apk(const char *ca_name, const char *modulus, const char *pub_exponent)
{
    tlogd("teelib add ca apk\n");
    return add_ca_apk(ca_name, modulus, pub_exponent);
}

static bool check_native_ca(const struct ca_exec_info *cand_exec, const struct ca_exec_info *allowed_exec)
{
    return ((cand_exec->pkg_name_len == strlen(allowed_exec->pkg_name)) &&
            (!TEE_MemCompare(cand_exec->pkg_name, allowed_exec->pkg_name, strlen(allowed_exec->pkg_name))) &&
            (cand_exec->uid == allowed_exec->uid));
}

static bool check_apk_ca(const struct ca_apk_info *cand_apk, const struct ca_apk_info *allowed_apk)
{
    return ((cand_apk->pkg_name_len == strlen(allowed_apk->pkg_name)) &&
            (!TEE_MemCompare(cand_apk->pkg_name, allowed_apk->pkg_name, strlen(allowed_apk->pkg_name))) &&
            (cand_apk->modulus_len == allowed_apk->modulus_len) &&
            (cand_apk->pub_exp_len == allowed_apk->pub_exp_len) &&
            (!TEE_MemCompare(cand_apk->modulus, allowed_apk->modulus, allowed_apk->modulus_len)) &&
            (!TEE_MemCompare(cand_apk->pub_exponent, allowed_apk->pub_exponent, allowed_apk->pub_exp_len)));
}

TEE_Result get_caller_candinfo(
    struct tee_caller_info *cand, const TEE_Param params[TA_COMMAND_TEE_PARAM_NUM], char *sig_buf)
{
    const uint32_t max_pkgname_len = get_max_pkgname_len();

    if (cand == NULL) {
        tloge("cand in Null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool flag = is_invalid_param(params, max_pkgname_len);
    if (flag == true) {
        tloge("params is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[CA_PARAM_CERT_INDEX].memref.size == sizeof(int)) {
        cand->caller_type |= CALLER_CA_UID;
        cand->caller.ca_exec.uid = *((uint32_t *)sig_buf);
    } else {
        TEE_Result res = get_cand_sign_info(params, cand, sig_buf);
        if (res != TEE_SUCCESS)
            return res;
    }

    return TEE_SUCCESS;
}

TEE_Result check_perm(const struct tee_caller_info *allowed_caller, const struct tee_caller_info *candidate, bool *flag)
{
    const struct ca_exec_info *cand_exec = NULL;
    const struct ca_exec_info *allowed_exec = NULL;
    const struct ca_apk_info *cand_apk = NULL;
    const struct ca_apk_info *allowed_apk = NULL;

    if (allowed_caller == NULL || candidate == NULL || flag == NULL) {
        tloge("Input Parameter is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    switch (candidate->caller_type) {
    case (CALLER_TYPE_CA | CALLER_CA_NAME | CALLER_CA_UID):
        cand_exec = &(candidate->caller.ca_exec);
        allowed_exec = &(allowed_caller->caller.ca_exec);
        (*flag) = check_native_ca(cand_exec, allowed_exec);
        break;
    case (CALLER_TYPE_CA | CALLER_CA_NAME | CALLER_CA_SIGN):
        cand_apk = &(candidate->caller.ca_apk);
        allowed_apk = &(allowed_caller->caller.ca_apk);
        (*flag) = check_apk_ca(cand_apk, allowed_apk);
        break;
    default:
        tloge("caller's type is not supported\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}
