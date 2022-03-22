/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HSM server client msg communication management.
 * Author: chenyao
 * Create: 2020-01-08
 * Notes:
 * History: 2020-01-08 chenyao create hsm_crypto api functions.
 */
#include <stdarg.h>
#include "ta_framework.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include "tee_obj.h"
#include "securec.h"
#include "string.h"
#include "tee_service_public.h"
#include "hsm_crypto_api.h"
#include "hsm_public.h"
#include "hsm_crypto_internal.h"

TEE_Result TEE_HSM_CipherStart(uint32_t dev_id, HSM_CIPHER_START_INFO *cipher_start_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = 0;

    ret = cipher_init_para_check(cipher_start_info);
    if (ret != TEE_SUCCESS) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = cipher_init_request_sharemem(&buffer_local, &buffer_size, cipher_start_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_ALG_SIZE) << HSM_CONST_SHIFT_32) |
        (uint64_t)(cipher_start_info->cipher_key.cryptokeyelementsize + HSM_KEY_ELEMENT_SIZE);
    msg.args_data.arg3 = (((uint64_t)(cipher_start_info->cipherkey_authsize + HSM_IV_SIZE)) << HSM_CONST_SHIFT_32) |
        (uint64_t)(cipher_start_info->cipherkey_authsize + HSM_KEY_PROTECT_SIZE);
    msg.args_data.arg4 = (((uint64_t)(cipher_start_info->iv_size)) << HSM_CONST_SHIFT_32) |
        (uint64_t)(cipher_start_info->crypto_service);
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_CIPHER_START_CMD, &msg, HSM_CIPHER_START_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        *cipher_start_info->session_handle = *(uint32_t *)(buffer_local);
        *cipher_start_info->max_chunk_size = HSM_CHUNK_SIZE;
        *cipher_start_info->chunk_block_size = HSM_BLOCK_SIZE;
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);

    return ret;
}

TEE_Result TEE_HSM_CipherProcess(uint32_t dev_id, HSM_CIPHER_PROCESS_INFO *cipher_process_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if ((cipher_process_info == NULL) || (cipher_process_info->input_data == NULL) ||
        (cipher_process_info->input_data_size > HSM_CHUNK_SIZE)) {
        goto HSM_CIPHER_PROCESS_Ex_Handle;
    }

    if ((cipher_process_info->output_data == NULL) || (cipher_process_info->output_data_size == NULL)) {
        goto HSM_CIPHER_PROCESS_Ex_Handle;
    }

    if (memmove_s(buffer_local, HSM_SESSION_HANDLE_SIZE,
        &(cipher_process_info->session_handle), HSM_SESSION_HANDLE_SIZE) != EOK) {
        goto HSM_CIPHER_PROCESS_Ex_Handle;
    }

    if (memmove_s(buffer_local + HSM_SESSION_HANDLE_SIZE, cipher_process_info->input_data_size,
        cipher_process_info->input_data, cipher_process_info->input_data_size) != EOK) {
        goto HSM_CIPHER_PROCESS_Ex_Handle;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_SESSION_HANDLE_SIZE) << HSM_CONST_SHIFT_32) |
        (uint64_t)(cipher_process_info->input_data_size);
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_CIPHER_PROCESS_CMD, &msg, HSM_CIPHER_PROCESS_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        *cipher_process_info->output_data_size = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if ((*cipher_process_info->output_data_size != 0) &&
            (memmove_s(cipher_process_info->output_data, *cipher_process_info->output_data_size, buffer_local,
                *cipher_process_info->output_data_size) != EOK)) {
            goto HSM_CIPHER_PROCESS_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);

    return ret;

HSM_CIPHER_PROCESS_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_CipherFinish(uint32_t dev_id, HSM_CIPHER_FINISH_INFO *cipher_finish_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if ((cipher_finish_info == NULL) || (cipher_finish_info->output_data == NULL) ||
        (cipher_finish_info->output_data_size == NULL)) {
        goto HSM_CIPHER_FINISH_Ex_Handle;
    }

    if (memmove_s(buffer_local, HSM_SESSION_HANDLE_SIZE,
        &(cipher_finish_info->session_handle), HSM_SESSION_HANDLE_SIZE) != EOK) {
        goto HSM_CIPHER_FINISH_Ex_Handle;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_SESSION_HANDLE_SIZE) << HSM_CONST_SHIFT_32) | HSM_MSG_RESUME;
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_CIPHER_FINISH_CMD, &msg, HSM_CIPHER_FINISH_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        *cipher_finish_info->output_data_size = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if (memmove_s(cipher_finish_info->output_data, *cipher_finish_info->output_data_size, buffer_local,
            *cipher_finish_info->output_data_size) != EOK) {
            goto HSM_CIPHER_FINISH_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);

    return ret;

HSM_CIPHER_FINISH_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_HashStart(uint32_t dev_id, HSM_HASH_START_INFO *hash_start_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = 0;

    ret = hash_init_para_check(hash_start_info);
    if (ret != TEE_SUCCESS) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = hash_init_request_sharemem(&buffer_local, &buffer_size, hash_start_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_ALG_SIZE) << HSM_CONST_SHIFT_32) | HSM_MSG_RESUME;
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_HASH_START_CMD, &msg, HSM_HASH_START_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        *hash_start_info->session_handle = *(uint32_t *)(buffer_local);
        *hash_start_info->max_chunk_size = HSM_CHUNK_SIZE;
        *hash_start_info->chunk_block_size = HSM_BLOCK_SIZE;
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;
}

TEE_Result TEE_HSM_HashProcess(uint32_t dev_id, HSM_HASH_PROCESS_INFO *hash_process_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if ((hash_process_info == NULL) || (hash_process_info->input_data == NULL) ||
        (hash_process_info->input_data_size > HSM_CHUNK_SIZE)) {
        goto HSM_HASH_PROCESS_Ex_Handle;
    }

    if (memmove_s(buffer_local, HSM_SESSION_HANDLE_SIZE, &(hash_process_info->session_handle),
        HSM_SESSION_HANDLE_SIZE) != EOK) {
        goto HSM_HASH_PROCESS_Ex_Handle;
    }

    if (memmove_s(buffer_local + HSM_SESSION_HANDLE_SIZE, hash_process_info->input_data_size,
        hash_process_info->input_data, hash_process_info->input_data_size) != EOK) {
        goto HSM_HASH_PROCESS_Ex_Handle;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_SESSION_HANDLE_SIZE) << HSM_CONST_SHIFT_32) |
        (uint64_t)(hash_process_info->input_data_size);
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_HASH_PROCESS_CMD, &msg, HSM_HASH_PROCESS_CMD, &rsp);

    ret = rsp.ret;
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_HASH_PROCESS_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_HashFinish(uint32_t dev_id, HSM_HASH_FINISH_INFO *hash_finish_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if ((hash_finish_info == NULL) || (hash_finish_info->output_data == NULL) ||
        (hash_finish_info->output_data_size == NULL)) {
        goto HSM_HASH_FINISH_Ex_Handle;
    }

    if (memmove_s(buffer_local, HSM_SESSION_HANDLE_SIZE, &(hash_finish_info->session_handle),
        HSM_SESSION_HANDLE_SIZE) != EOK) {
        goto HSM_HASH_FINISH_Ex_Handle;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_SESSION_HANDLE_SIZE) << HSM_CONST_SHIFT_32) | HSM_MSG_RESUME;
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_HASH_FINISH_CMD, &msg, HSM_HASH_FINISH_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        *hash_finish_info->output_data_size = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if (memmove_s(hash_finish_info->output_data, *hash_finish_info->output_data_size, buffer_local,
            *hash_finish_info->output_data_size) != EOK) {
            goto HSM_HASH_FINISH_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_HASH_FINISH_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_MacStart(uint32_t dev_id, HSM_MAC_START_INFO *mac_start_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size;

    ret = mac_init_para_check(mac_start_info);
    if (ret != TEE_SUCCESS) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = mac_init_request_sharemem(&buffer_local, &buffer_size, mac_start_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_ALG_SIZE) << HSM_CONST_SHIFT_32) |
        (uint64_t)(mac_start_info->cipher_key.cryptokeyelementsize + HSM_KEY_ELEMENT_SIZE);
    msg.args_data.arg3 = (((uint64_t)(mac_start_info->cipherkey_authsize + HSM_IV_SIZE)) << HSM_CONST_SHIFT_32) |
        (uint64_t)(mac_start_info->cipherkey_authsize + HSM_KEY_PROTECT_SIZE);
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_MAC_START_CMD, &msg, HSM_MAC_START_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        *mac_start_info->session_handle = *(uint32_t *)(buffer_local);
        *mac_start_info->max_chunk_size = HSM_CHUNK_SIZE;
        *mac_start_info->chunk_block_size = HSM_BLOCK_SIZE;
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;
}

TEE_Result TEE_HSM_MacProcess(uint32_t dev_id, HSM_MAC_PROCESS_INFO *mac_process_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if ((mac_process_info == NULL) || (mac_process_info->input_data == NULL) ||
        (mac_process_info->input_data_size > HSM_CHUNK_SIZE)) {
        goto HSM_MAC_PROCESS_Ex_Handle;
    }

    if (memmove_s(buffer_local, HSM_SESSION_HANDLE_SIZE, &(mac_process_info->session_handle),
        HSM_SESSION_HANDLE_SIZE) != EOK) {
        goto HSM_MAC_PROCESS_Ex_Handle;
    }

    if (memmove_s(buffer_local + HSM_SESSION_HANDLE_SIZE, mac_process_info->input_data_size,
        mac_process_info->input_data, mac_process_info->input_data_size) != EOK) {
        goto HSM_MAC_PROCESS_Ex_Handle;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_SESSION_HANDLE_SIZE) << HSM_CONST_SHIFT_32) |
        (uint64_t)(mac_process_info->input_data_size);
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_MAC_PROCESS_CMD, &msg, HSM_MAC_PROCESS_CMD, &rsp);

    ret = rsp.ret;
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_MAC_PROCESS_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_MacFinish(uint32_t dev_id, HSM_MAC_FINISH_INFO *mac_finish_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if ((mac_finish_info == NULL) || (mac_finish_info->output_data == NULL) ||
        (mac_finish_info->output_data_size == NULL)) {
        goto HSM_MAC_FINISH_Ex_Handle;
    }

    if (memmove_s(buffer_local, HSM_SESSION_HANDLE_SIZE, &(mac_finish_info->session_handle),
        HSM_SESSION_HANDLE_SIZE) != EOK) {
        goto HSM_MAC_FINISH_Ex_Handle;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_SESSION_HANDLE_SIZE) << HSM_CONST_SHIFT_32) | HSM_MSG_RESUME;
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_MAC_FINISH_CMD, &msg, HSM_MAC_FINISH_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        *mac_finish_info->output_data_size = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if (memmove_s(mac_finish_info->output_data, *mac_finish_info->output_data_size, buffer_local,
            *mac_finish_info->output_data_size) != EOK) {
            goto HSM_MAC_FINISH_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_MAC_FINISH_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_SignStart(uint32_t dev_id, HSM_SIGN_START_INFO *sign_start_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size;

    ret = sign_init_para_check(sign_start_info);
    if (ret != TEE_SUCCESS) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = sign_init_request_sharemem(&buffer_local, &buffer_size, sign_start_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_ALG_SIZE) << HSM_CONST_SHIFT_32) |
        (uint64_t)(sign_start_info->cipher_key.cryptokeyelementsize + HSM_KEY_ELEMENT_SIZE);
    msg.args_data.arg3 = (((uint64_t)(sign_start_info->cipherkey_authsize + HSM_IV_SIZE)) << HSM_CONST_SHIFT_32) |
        (uint64_t)(sign_start_info->cipherkey_authsize + HSM_KEY_PROTECT_SIZE);
    msg.args_data.arg4 = (((uint64_t)HSM_SALT_SIZE) << HSM_CONST_SHIFT_32) | HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_SIGN_START_CMD, &msg, HSM_SIGN_START_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        *sign_start_info->session_handle = *(uint32_t *)(buffer_local);
        *sign_start_info->max_chunk_size = HSM_CHUNK_SIZE;
        *sign_start_info->chunk_block_size = HSM_BLOCK_SIZE;
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;
}

TEE_Result TEE_HSM_SignProcess(uint32_t dev_id, HSM_SIGN_PROCESS_INFO *sign_process_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if ((sign_process_info == NULL) || (sign_process_info->input_data == NULL) ||
        (sign_process_info->input_data_size > HSM_CHUNK_SIZE)) {
        goto HSM_SIGN_PROCESS_Ex_Handle;
    }

    if (memmove_s(buffer_local, HSM_SESSION_HANDLE_SIZE,
        &(sign_process_info->session_handle), HSM_SESSION_HANDLE_SIZE) != EOK) {
        goto HSM_SIGN_PROCESS_Ex_Handle;
    }

    if (memmove_s(buffer_local + HSM_SESSION_HANDLE_SIZE, sign_process_info->input_data_size,
        sign_process_info->input_data, sign_process_info->input_data_size) != EOK) {
        goto HSM_SIGN_PROCESS_Ex_Handle;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_SESSION_HANDLE_SIZE) << HSM_CONST_SHIFT_32) |
        (uint64_t)(sign_process_info->input_data_size);
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_SIGN_PROCESS_CMD, &msg, HSM_SIGN_PROCESS_CMD, &rsp);

    ret = rsp.ret;
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_SIGN_PROCESS_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_SignFinish(uint32_t dev_id, HSM_SIGN_FINISH_INFO *sign_finish_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if ((sign_finish_info == NULL) || (sign_finish_info->sign == NULL) ||
        (sign_finish_info->sign_size == NULL)) {
        goto HSM_SIGN_FINISH_Ex_Handle;
    }

    if (memmove_s(buffer_local, HSM_SESSION_HANDLE_SIZE,
        &(sign_finish_info->session_handle), HSM_SESSION_HANDLE_SIZE) != EOK) {
        goto HSM_SIGN_FINISH_Ex_Handle;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_SESSION_HANDLE_SIZE) << HSM_CONST_SHIFT_32) | HSM_MSG_RESUME;
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_SIGN_FINISH_CMD, &msg, HSM_SIGN_FINISH_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        *sign_finish_info->sign_size = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if (memmove_s(sign_finish_info->sign, *sign_finish_info->sign_size, buffer_local,
            *sign_finish_info->sign_size) != EOK) {
            goto HSM_SIGN_FINISH_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_SIGN_FINISH_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_VerifyStart(uint32_t dev_id, HSM_VERIFY_START_INFO *verify_start_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = 0;

    ret = verify_init_para_check(verify_start_info);
    if (ret != TEE_SUCCESS) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = verify_init_request_sharemem(&buffer_local, &buffer_size, verify_start_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_ALG_SIZE) << HSM_CONST_SHIFT_32) |
        (uint64_t)(verify_start_info->cipher_key.cryptokeyelementsize + HSM_KEY_ELEMENT_SIZE);
    msg.args_data.arg3 = (((uint64_t)(verify_start_info->cipherkey_authsize + HSM_IV_SIZE)) << HSM_CONST_SHIFT_32) |
        (uint64_t)(verify_start_info->cipherkey_authsize + HSM_KEY_PROTECT_SIZE);
    msg.args_data.arg4 = (((uint64_t)(HSM_SALT_SIZE)) << HSM_CONST_SHIFT_32) |
        ((uint64_t)(verify_start_info->sign_size));
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_VERIFY_START_CMD, &msg, HSM_VERIFY_START_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        *verify_start_info->session_handle = *(uint32_t *)(buffer_local);
        *verify_start_info->max_chunk_size = HSM_CHUNK_SIZE;
        *verify_start_info->chunk_block_size = HSM_BLOCK_SIZE;
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;
}

TEE_Result TEE_HSM_VerifyProcess(uint32_t dev_id, HSM_VERIFY_PROCESS_INFO *verify_process_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if ((verify_process_info == NULL) || (verify_process_info->input_data == NULL) ||
        (verify_process_info->input_data_size > HSM_CHUNK_SIZE)) {
        goto HSM_VERIFY_PROCESS_Ex_Handle;
    }

    if (memmove_s(buffer_local, HSM_SESSION_HANDLE_SIZE,
        &(verify_process_info->session_handle), HSM_SESSION_HANDLE_SIZE) != EOK) {
        goto HSM_VERIFY_PROCESS_Ex_Handle;
    }

    if (memmove_s(buffer_local + HSM_SESSION_HANDLE_SIZE, verify_process_info->input_data_size,
        verify_process_info->input_data, verify_process_info->input_data_size) != EOK) {
        goto HSM_VERIFY_PROCESS_Ex_Handle;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_SESSION_HANDLE_SIZE) << HSM_CONST_SHIFT_32) |
        (uint64_t)(verify_process_info->input_data_size);
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_VERIFY_PROCESS_CMD, &msg, HSM_VERIFY_PROCESS_CMD, &rsp);

    ret = rsp.ret;
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_VERIFY_PROCESS_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_VerifyFinish(uint32_t dev_id, HSM_VERIFY_FINISH_INFO *verify_finish_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (verify_finish_info == NULL || verify_finish_info->verify_result == NULL) {
        goto HSM_VERIFY_FINISH_Ex_Handle;
    }

    if (memmove_s(buffer_local, HSM_SESSION_HANDLE_SIZE,
        &(verify_finish_info->session_handle), HSM_SESSION_HANDLE_SIZE) != EOK) {
        goto HSM_VERIFY_FINISH_Ex_Handle;
    }

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_SESSION_HANDLE_SIZE) << HSM_CONST_SHIFT_32) | HSM_MSG_RESUME;
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_VERIFY_FINISH_CMD, &msg, HSM_VERIFY_FINISH_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        *verify_finish_info->verify_result = HSM_VER_SUCCESS;
    } else {
        *verify_finish_info->verify_result = HSM_VER_FAIL;
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_VERIFY_FINISH_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_GetRandom(uint32_t dev_id, HSM_GET_RANDOM_INFO *random_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;
    uint32_t size0;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if ((random_info == NULL) || (random_info->random == NULL)) {
        goto HSM_GET_RANDOM_Ex_Handle;
    }

    if (memmove_s(buffer_local, HSM_RANDOM_SIZE, &(random_info->random_size), HSM_RANDOM_SIZE) != EOK)
        goto HSM_GET_RANDOM_Ex_Handle;

    rsp.ret = TEE_FAIL;
    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_RANDOM_SIZE) << HSM_CONST_SHIFT_32) | HSM_MSG_RESUME;
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_GET_RANDOM_CMD, &msg, HSM_GET_RANDOM_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if (memmove_s(random_info->random, size0, buffer_local, size0) != EOK) {
            goto HSM_GET_RANDOM_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_GET_RANDOM_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}
