/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: HSM kms api function.
 * Author: chenyao
 * Create: 2020-01-08
 * Notes:
 * History: 2020-01-08 chenyao create hsm_kms api functions.
 */
#include <stdarg.h>
#include "mem_ops_ext.h"
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_obj.h"
#include "securec.h"
#include "string.h"
#include "tee_service_public.h"
#include "hsm_kms_api.h"
#include "hsm_public.h"
#include "hsm_kms_internal.h"

TEE_Result TEE_HSM_GenSymeticKey(uint32_t dev_id, HSM_GENERATE_SYMKEY_INFO *generate_symkey_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size;
    uint32_t size0;
    uint32_t size1;
    uint32_t state;

    ret = generate_symkey_para_check(generate_symkey_info);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = generate_symkey_request_sharemem(&buffer_local, &buffer_size, generate_symkey_info);
    if (ret != TEE_SUCCESS)
        return ret;

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_ALG_SIZE) << HSM_CONST_SHIFT_32) | (uint64_t)(HSM_KEY_ELEMENT_SIZE);
    msg.args_data.arg3 = (((uint64_t)generate_symkey_info->symkey_authsize + HSM_IV_SIZE) << HSM_CONST_SHIFT_32)
        | HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_GENERATE_SYMKEY_CMD, &msg, HSM_GENERATE_SYMKEY_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32) - HSM_KEY_ELEMENT_SIZE;
        size1 = (uint32_t)(rsp.msg.args_data.arg2);
        if (size0 > HSM_SYMKEY_MAX_SIZE || size1 > HSM_PROTECTMSG_MAX_SIZE) {
            goto HSM_GEN_SYMKEY_Ex_Handle;
        }
        state = memmove_s(generate_symkey_info->symkey.cryptokeyelementvalueref, size0,
            buffer_local + HSM_KEY_ELEMENT_SIZE, size0);
        if (state != EOK) {
            goto HSM_GEN_SYMKEY_Ex_Handle;
        }
        state = memmove_s(generate_symkey_info->symkey_protectmsg, size1,
            buffer_local + size0 + HSM_KEY_ELEMENT_SIZE, size1);
        if (state != EOK) {
            goto HSM_GEN_SYMKEY_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_GEN_SYMKEY_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_GenAsymeticKey(uint32_t dev_id, HSM_GENERATE_ASYMKEY_INFO *generate_asymkey_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size;
    uint32_t state;

    ret = generate_asymkey_para_check(generate_asymkey_info);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = generate_asymkey_request_sharemem(&buffer_local, &buffer_size, generate_asymkey_info);
    if (ret != TEE_SUCCESS)
        return ret;

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_ALG_SIZE) << HSM_CONST_SHIFT_32) | (uint64_t)(HSM_KEY_ELEMENT_SIZE);
    msg.args_data.arg3 = (((uint64_t)HSM_KEY_ELEMENT_SIZE) << HSM_CONST_SHIFT_32) |
        (((uint64_t)generate_asymkey_info->key_authsize + HSM_IV_SIZE));
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_GENERATE_ASYMKEY_CMD, &msg, HSM_GENERATE_ASYMKEY_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        state = hsm_asymetickey_rsp(&rsp, generate_asymkey_info, buffer_local);
        if (state != TEE_SUCCESS) {
            goto HSM_GEN_ASYMKEY_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_GEN_ASYMKEY_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_DeriveHuk(uint32_t dev_id, HSM_DERIVE_HUK_INFO *derive_huk_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size;
    uint32_t size0;
    uint32_t size1;

    ret = derive_huk_para_check(derive_huk_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = derive_huk_request_sharemem(&buffer_local, &buffer_size, derive_huk_info);
    if (ret != TEE_SUCCESS)
        return ret;

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)(HSM_DERIVE_KEY_HEAD + derive_huk_info->salt_size)) << HSM_CONST_SHIFT_32) |
        (uint64_t)(HSM_KEY_ELEMENT_SIZE);
    msg.args_data.arg3 = (((uint64_t)derive_huk_info->key_authsize + HSM_IV_SIZE) << HSM_CONST_SHIFT_32) |
        HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_DERIVE_HUK_CMD, &msg, HSM_DERIVE_HUK_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32) - HSM_KEY_ELEMENT_SIZE;
        size1 = (uint32_t)(rsp.msg.args_data.arg2);
        if ((size0 > HSM_ASYMKEY_MAX_SIZE) || (size1 > HSM_PROTECTMSG_MAX_SIZE)) {
            goto HSM_DERIVE_HUK_Ex_Handle;
        }
        if (memmove_s(derive_huk_info->c_key.cryptokeyelementvalueref, size0,
            buffer_local + HSM_KEY_ELEMENT_SIZE, size0) != EOK) {
            goto HSM_DERIVE_HUK_Ex_Handle;
        }
        if (memmove_s(derive_huk_info->key_protectmsg, size1,
            buffer_local + size0 + HSM_KEY_ELEMENT_SIZE, size1) != EOK) {
            goto HSM_DERIVE_HUK_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_DERIVE_HUK_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_DeriveKey(uint32_t dev_id, HSM_DERIVE_KEY_INFO *derive_key_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size;
    uint32_t size0;
    uint32_t size1;

    ret = derive_key_para_check(derive_key_info);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = derive_key_request_sharemem(&buffer_local, &buffer_size, derive_key_info);
    if (ret != TEE_SUCCESS)
        return ret;

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_KEY_HEAD_SIZE + derive_key_info->salt_size) << HSM_CONST_SHIFT_32) |
        (uint64_t)(HSM_KEY_ELEMENT_SIZE);
    msg.args_data.arg3 = (((uint64_t)derive_key_info->target_key_authsize + HSM_IV_SIZE) << HSM_CONST_SHIFT_32) |
        ((uint64_t)derive_key_info->source_key.cryptokeyelementsize + HSM_KEY_ELEMENT_SIZE);
    msg.args_data.arg4 = (((uint64_t)derive_key_info->source_key_authsize + HSM_IV_SIZE) << HSM_CONST_SHIFT_32) |
        ((uint64_t)derive_key_info->source_key_authsize + HSM_KEY_PROTECT_SIZE);
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_DERIVE_KEY_CMD, &msg, HSM_DERIVE_KEY_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32) - HSM_KEY_ELEMENT_SIZE;
        size1 = (uint32_t)(rsp.msg.args_data.arg2);
        if (size0 > HSM_ASYMKEY_MAX_SIZE || size1 > HSM_PROTECTMSG_MAX_SIZE) {
            goto HSM_DERIVE_KEY_Ex_Handle;
        }
        if (memmove_s(derive_key_info->target_key.cryptokeyelementvalueref, size0,
            buffer_local + HSM_KEY_ELEMENT_SIZE, size0) != EOK) {
            goto HSM_DERIVE_KEY_Ex_Handle;
        }
        if (memmove_s(derive_key_info->target_key_protectmsg, size1,
            buffer_local + size0 + HSM_KEY_ELEMENT_SIZE, size1) != EOK) {
            goto HSM_DERIVE_KEY_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_DERIVE_KEY_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_ImportKey(uint32_t dev_id, HSM_IMPORT_KEY_INFO *import_key_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size;
    uint32_t size0;
    uint32_t size1;

    ret = import_key_para_check(import_key_info);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = import_key_request_sharemem(&buffer_local, &buffer_size, import_key_info);
    if (ret != TEE_SUCCESS)
        return ret;

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)(HSM_KEY_HEAD_SIZE + import_key_info->salt_size)) << HSM_CONST_SHIFT_32) |
        (uint64_t)(import_key_info->import_key.cryptokeyelementsize + HSM_KEY_INFO_SIZE);
    msg.args_data.arg3 = (((uint64_t)HSM_KEY_ELEMENT_SIZE) << HSM_CONST_SHIFT_32) |
        ((uint64_t)(import_key_info->import_key_authsize + HSM_IV_SIZE));
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_IMPORT_KEY_CMD, &msg, HSM_IMPORT_KEY_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32) - HSM_KEY_ELEMENT_SIZE;
        size1 = (uint32_t)(rsp.msg.args_data.arg2);
        if ((size0 > HSM_ASYMKEY_MAX_SIZE) || (size1 > HSM_PROTECTMSG_MAX_SIZE)) {
            goto HSM_IMPORT_KEY_Ex_Handle;
        }
        if (memmove_s(import_key_info->import_key.cryptokeyelementvalueref, size0,
            buffer_local + HSM_KEY_ELEMENT_SIZE, size0) != EOK) {
            goto HSM_IMPORT_KEY_Ex_Handle;
        }
        if (memmove_s(import_key_info->import_key_protectmsg, size1,
            buffer_local + size0 + HSM_KEY_ELEMENT_SIZE, size1) != EOK) {
            goto HSM_IMPORT_KEY_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_IMPORT_KEY_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_ExchangePubKey(uint32_t dev_id, HSM_EXCHANGE_PUBKEY_INFO *exchange_pubkey)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size;
    uint32_t size0;

    ret = exchange_pubkey_para_check(exchange_pubkey);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = exchange_pubkey_request_sharemem(&buffer_local, &buffer_size, exchange_pubkey);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_ALG_SIZE) << HSM_CONST_SHIFT_32) |
        (uint64_t)(HSM_KEY_ELEMENT_SIZE + exchange_pubkey->exchange_pubkey.cryptokeyelementsize);
    msg.args_data.arg3 = (((uint64_t)(HSM_IV_SIZE + exchange_pubkey->exchange_pubkey_authsize)) <<HSM_CONST_SHIFT_32) |
        ((uint64_t)(HSM_KEY_PROTECT_SIZE + exchange_pubkey->exchange_pubkey_authsize));
    msg.args_data.arg4 = (((uint64_t)HSM_DOMAIN_SIZE) << HSM_CONST_SHIFT_32) | HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_EXCHANGE_CAL_PUB_CMD, &msg, HSM_EXCHANGE_CAL_PUB_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if (size0 > HSM_ASYMKEY_MAX_SIZE) {
            goto HSM_EXCHANGE_PUBKEY_Ex_Handle;
        }
        exchange_pubkey->generate_pubkey_len = size0;
        if (memmove_s(exchange_pubkey->exchange_pubkey.cryptokeyelementvalueref, size0, buffer_local, size0) != EOK) {
            goto HSM_EXCHANGE_PUBKEY_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_EXCHANGE_PUBKEY_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_ExchangeAgreeKey(uint32_t dev_id, HSM_EXCHANGE_KEY_INFO *exchange_agree_key)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size;
    uint32_t size0;
    uint32_t size1;

    ret = exchange_agree_key_para_check(exchange_agree_key);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = exchange_agree_key_request_sharemem(&buffer_local, &buffer_size, exchange_agree_key);
    if (ret != TEE_SUCCESS)
        return ret;

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_ALG_SIZE) << HSM_KEY_ELEMENT_SIZE) |
        (uint64_t)(HSM_KEY_ELEMENT_SIZE + exchange_agree_key->exchange_prikey.cryptokeyelementsize);
    msg.args_data.arg3 = (((uint64_t)(HSM_IV_SIZE +
        exchange_agree_key->exchange_prikey_authsize)) <<HSM_CONST_SHIFT_32) |
        ((uint64_t)(HSM_KEY_PROTECT_SIZE + exchange_agree_key->exchange_prikey_authsize));
    msg.args_data.arg4 = (((uint64_t)(exchange_agree_key->exchange_pubkey_len)) << HSM_KEY_ELEMENT_SIZE) |
        ((uint64_t)HSM_KEY_ELEMENT_SIZE);
    msg.args_data.arg5 = (((uint64_t)(HSM_IV_SIZE +
        exchange_agree_key->exchange_key_authsize)) << HSM_CONST_SHIFT_32) | (uint64_t)(HSM_DOMAIN_SIZE);
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_EXCHANGE_AGREE_KEY_CMD, &msg, HSM_EXCHANGE_AGREE_KEY_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32) - HSM_KEY_ELEMENT_SIZE;
        size1 = (uint32_t)(rsp.msg.args_data.arg2);
        if ((size0 > HSM_ASYMKEY_MAX_SIZE) || (size1 > HSM_AUTH_MAX_SIZE)) {
            goto HSM_EXCHANGE_KEY_Ex_Handle;
        }

        if (memmove_s(exchange_agree_key->exchange_key.cryptokeyelementvalueref, size0,
            buffer_local + HSM_KEY_ELEMENT_SIZE, size0) != EOK) {
            goto HSM_EXCHANGE_KEY_Ex_Handle;
        }

        if (memmove_s(exchange_agree_key->exchange_key_protectmsg, size1,
            buffer_local + size0 + HSM_KEY_ELEMENT_SIZE, size1) != EOK) {
            goto HSM_EXCHANGE_KEY_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_EXCHANGE_KEY_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_UpdateProtectMsg(uint32_t dev_id, HSM_UPDATE_PROKEY_INFO *update_prokey_info)

{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size;
    uint32_t size0;
    uint32_t size1;

    ret = update_prokey_para_check(update_prokey_info);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = update_prokey_request_sharemem(&buffer_local, &buffer_size, update_prokey_info);
    if (ret != TEE_SUCCESS)
        return ret;

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = ((uint64_t)(HSM_KEY_ELEMENT_SIZE +
        update_prokey_info->prokey.cryptokeyelementsize) << HSM_CONST_SHIFT_32) |
        (uint64_t)(HSM_IV_SIZE + update_prokey_info->prokey_authsize);
    msg.args_data.arg3 = ((uint64_t)(HSM_KEY_PROTECT_SIZE +
        update_prokey_info->prokey_authsize) << HSM_CONST_SHIFT_32) | HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_UPDATE_PROTECT_KEY_CMD, &msg, HSM_UPDATE_PROTECT_KEY_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32) - HSM_KEY_ELEMENT_SIZE;
        size1 = (uint32_t)(rsp.msg.args_data.arg2);
        if ((size0 > HSM_ASYMKEY_MAX_SIZE) || (size1 > HSM_PROTECTMSG_MAX_SIZE)) {
            goto HSM_UPDATE_PROTECT_KEY_Ex_Handle;
        }

        if (memmove_s(update_prokey_info->prokey.cryptokeyelementvalueref, size0,
            buffer_local + HSM_KEY_ELEMENT_SIZE, size0) != EOK) {
            goto HSM_UPDATE_PROTECT_KEY_Ex_Handle;
        }

        if (memmove_s(update_prokey_info->prokey_protectmsg, size1,
            buffer_local + size0 + HSM_KEY_ELEMENT_SIZE, size1) != EOK) {
            goto HSM_UPDATE_PROTECT_KEY_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_UPDATE_PROTECT_KEY_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_UpdateAuth(uint32_t dev_id, HSM_UPDATE_KEYAUTH_INFO *update_keyauth_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size;
    uint32_t size0;
    uint32_t state;

    ret = update_keyauth_para_check(update_keyauth_info);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = update_keyauth_request_sharemem(&buffer_local, &buffer_size, update_keyauth_info);
    if (ret != TEE_SUCCESS)
        return ret;

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = ((uint64_t)(HSM_IV_SIZE + update_keyauth_info->past_key_authsize) << HSM_CONST_SHIFT_32) |
        (uint64_t)(HSM_KEY_PROTECT_SIZE + update_keyauth_info->past_key_authsize);
    msg.args_data.arg3 = ((uint64_t)(HSM_IV_SIZE + update_keyauth_info->new_key_authsize) << HSM_CONST_SHIFT_32) |
        HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_UPDATE_KEY_AUTH_CMD, &msg, HSM_UPDATE_KEY_AUTH_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if (size0 > HSM_PROTECTMSG_MAX_SIZE) {
            goto HSM_UPDATE_AUTH_Ex_Handle;
        }
        state = memmove_s(update_keyauth_info->key_protectmsg, size0, buffer_local, size0);
        if (state != EOK) {
            goto HSM_UPDATE_AUTH_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_UPDATE_AUTH_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_DeleteKey(uint32_t dev_id, HSM_DELETE_KEY_INFO *delete_key_info)

{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size;

    ret = delete_key_para_check(delete_key_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = delete_key_request_sharemem(&buffer_local, &buffer_size, delete_key_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = ((uint64_t)(HSM_KEY_PROTECT_SIZE +
        delete_key_info->delete_key_authsize) << HSM_CONST_SHIFT_32) |
        (uint64_t)(HSM_IV_SIZE + delete_key_info->delete_key_authsize);
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_DELETE_KEY_CMD, &msg, HSM_DELETE_KEY_CMD, &rsp);

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return rsp.ret;
}

TEE_Result TEE_HSM_ExportKey(uint32_t dev_id, HSM_EXPORT_KEY_INFO *export_key_info)

{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size;
    uint32_t size0;

    ret = export_key_para_check(export_key_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = export_key_request_sharemem(&buffer_local, &buffer_size, export_key_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = ((uint64_t)(HSM_KEY_HEAD_SIZE + export_key_info->salt_size) << HSM_CONST_SHIFT_32) |
        (uint64_t)(HSM_KEY_ELEMENT_SIZE + export_key_info->export_key.cryptokeyelementsize);
    msg.args_data.arg3 = (((uint64_t)(HSM_IV_SIZE + export_key_info->export_key_authsize)) << HSM_CONST_SHIFT_32) |
        ((uint64_t)(HSM_KEY_PROTECT_SIZE + export_key_info->export_key_authsize));
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_EXPORT_KEY_CMD, &msg, HSM_EXPORT_KEY_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if (size0 > (HSM_ASYMKEY_MAX_SIZE + HSM_KEY_APPEND_SIZE)) {
            goto HSM_EXPORT_KEY_Ex_Handle;
        }
        if (memmove_s(export_key_info->export_key_info, size0, buffer_local, size0) != EOK) {
            goto HSM_EXPORT_KEY_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_EXPORT_KEY_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_Bbox(uint32_t dev_id, HSM_BBOX_INFO *hsm_bbox_info, uint64_t tv_sec, uint64_t tv_usec)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        tloge("TEE_HSM_Bbox, alloc smem failed!\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)(sizeof(uint64_t)) << HSM_CONST_SHIFT_32) + sizeof(uint64_t));
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    if (memmove_s(buffer_local, sizeof(uint64_t), &tv_sec, sizeof(uint64_t)) != EOK) {
        goto HSM_BBOX_Ex_Handle;
    }
    if (memmove_s(buffer_local + sizeof(uint64_t), sizeof(uint64_t), &tv_usec, sizeof(uint64_t)) != EOK) {
        goto HSM_BBOX_Ex_Handle;
    }

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_BBOX_CMD, &msg, HSM_BBOX_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        *hsm_bbox_info->state = *(uint32_t *)buffer_local;
    } else if (ret == TEE_ERROR_TIMEOUT) {
        *hsm_bbox_info->state = HSM_BBOX_TIMEOUT;
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_BBOX_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_notify_prereset(uint32_t dev_id)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    if (dev_id > 1) {
        return TEE_SUCCESS;
    }
    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        tloge("TEE_HSM_notify_prereset, alloc smem failed!\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = HSM_MSG_RESUME;
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_NOTIFY_PRERESET_CMD, &msg, HSM_NOTIFY_PRERESET_CMD, &rsp);
    ret = rsp.ret;
    tloge("TEE_HSM_notify_prereset ret=0x%x\n", ret);

    __SRE_MemFreeShared(buffer_local, buffer_size);

    return ret;

HSM_BBOX_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

