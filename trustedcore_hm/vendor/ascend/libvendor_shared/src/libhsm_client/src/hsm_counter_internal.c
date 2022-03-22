/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: HSM kms internal function.
 * Author: chenyao
 * Create: 2020-01-08
 * Notes:
 * History: 2020-01-08 chenyao create hsm_kms functions.
 */
#include <stdarg.h>
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_obj.h"
#include "securec.h"
#include "string.h"
#include "tee_service_public.h"
#include "hsm_counter_api.h"
#include "hsm_public.h"

TEE_Result counter_create_para_check(HSM_COUNT_CREATE_INFO *count_create_info)
{
    if ((count_create_info == NULL) || (count_create_info->counter_auth == NULL) ||
        (count_create_info->counter_info == NULL) || (count_create_info->counter_id == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if ((count_create_info->counter_auth_len > HSM_AUTH_MAX_SIZE) || (count_create_info->counter_auth_len == 0)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result counter_create_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_COUNT_CREATE_INFO *count_create_info)
{
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint32_t auth_size = count_create_info->counter_auth_len;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memcpy_s(*buffer_local, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        goto HSM_COUNTER_CREATE_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_IV_SIZE, count_create_info->counter_auth_len,
        count_create_info->counter_auth, auth_size) != EOK) {
        goto HSM_COUNTER_CREATE_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_IV_SIZE + auth_size, HSM_COUNTER_SIZE,
        count_create_info->counter_info, HSM_COUNTER_SIZE) != EOK) {
        goto HSM_COUNTER_CREATE_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

HSM_COUNTER_CREATE_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result counter_read_para_check(HSM_COUNT_READ_INFO *count_read_info)
{
    if ((count_read_info == NULL) || (count_read_info->count_value == NULL) ||
        (count_read_info->counter_info == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result counter_read_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_COUNT_READ_INFO *count_read_info)
{
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(*buffer_local, HSM_COUNTER_ID_SIZE, &count_read_info->counter_id, HSM_COUNTER_ID_SIZE) != EOK) {
        goto HSM_COUNTER_READ_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_COUNTER_ID_SIZE, HSM_COUNTER_SIZE,
        count_read_info->counter_info, HSM_COUNTER_SIZE) != EOK) {
        goto HSM_COUNTER_READ_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

HSM_COUNTER_READ_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result counter_delete_para_check(HSM_COUNT_DELETE_INFO *count_delete_info)
{
    if ((count_delete_info == NULL) || (count_delete_info->counter_auth == NULL) ||
        (count_delete_info->counter_info == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if ((count_delete_info->counter_auth_len > HSM_AUTH_MAX_SIZE) || (count_delete_info->counter_auth_len == 0)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result counter_delete_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_COUNT_DELETE_INFO *count_delete_info)
{
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint32_t auth_size = count_delete_info->counter_auth_len;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(*buffer_local, HSM_COUNTER_ID_SIZE, &count_delete_info->counter_id, HSM_COUNTER_ID_SIZE) != EOK) {
        goto HSM_COUNTER_DELETE_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_COUNTER_ID_SIZE, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        goto HSM_COUNTER_DELETE_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_COUNTER_ID_SIZE + HSM_IV_SIZE, auth_size,
        count_delete_info->counter_auth, auth_size) != EOK) {
        goto HSM_COUNTER_DELETE_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_COUNTER_ID_SIZE + HSM_IV_SIZE + auth_size, HSM_COUNTER_SIZE,
        count_delete_info->counter_info, HSM_COUNTER_SIZE) != EOK) {
        goto HSM_COUNTER_DELETE_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

HSM_COUNTER_DELETE_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}

TEE_Result counter_inc_para_check(HSM_COUNT_INC_INFO *count_inc_info)
{
    if ((count_inc_info == NULL) || (count_inc_info->counter_auth == NULL) ||
        (count_inc_info->counter_info == NULL) || (count_inc_info->counter_value == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if ((count_inc_info->counter_auth_len > HSM_AUTH_MAX_SIZE) || (count_inc_info->counter_auth_len == 0)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result counter_inc_request_sharemem(uint8_t **buffer_local, uint32_t *buffer_size,
    HSM_COUNT_INC_INFO *count_inc_info)
{
    uint32_t dst_size = HSM_CLIENT_DDR_LEN;
    uint32_t auth_size = count_inc_info->counter_auth_len;
    uint8_t tmp[HSM_IV_SIZE] = {0};

    *buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (*buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(*buffer_local, HSM_COUNTER_ID_SIZE, &count_inc_info->counter_id, HSM_COUNTER_ID_SIZE) != EOK) {
        goto HSM_COUNTER_INC_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_COUNTER_ID_SIZE, HSM_IV_SIZE, tmp, HSM_IV_SIZE) != EOK) {
        goto HSM_COUNTER_INC_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_COUNTER_ID_SIZE + HSM_IV_SIZE, auth_size,
        count_inc_info->counter_auth, auth_size) != EOK) {
        goto HSM_COUNTER_INC_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_COUNTER_ID_SIZE + HSM_IV_SIZE + auth_size, HSM_COUNTER_VALUE_SIZE,
        &count_inc_info->counter_value_add, HSM_COUNTER_VALUE_SIZE) != EOK) {
        goto HSM_COUNTER_INC_Ex_Handle;
    }

    if (memmove_s(*buffer_local + HSM_COUNTER_ID_SIZE + HSM_IV_SIZE + auth_size + HSM_COUNTER_VALUE_SIZE,
        HSM_COUNTER_SIZE, count_inc_info->counter_info, HSM_COUNTER_SIZE) != EOK) {
        goto HSM_COUNTER_INC_Ex_Handle;
    }

    *buffer_size = dst_size;
    return TEE_SUCCESS;

HSM_COUNTER_INC_Ex_Handle:
    tloge("%s\n", __func__);
    __SRE_MemFreeShared(*buffer_local, dst_size);
    *buffer_local = NULL;
    return TEE_ERROR_SECURITY;
}
