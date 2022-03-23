/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: HSM rpmb ak key provide api
 * Author: chenyao
 * Create: 2020-05-06
 * Notes:
 * History:
 */
#include <stdarg.h>
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_obj.h"
#include "securec.h"
#include "string.h"
#include "tee_service_public.h"
#include "hsm_rpmb_api.h"
#include "hsm_public.h"

TEE_Result TEE_HSM_GenRpmbKey(uint32_t dev_id, uint8_t *rpmb_key)
{
    tee_service_ipc_msg_rsp rsp = {0};
    tee_service_ipc_msg msg = {{0}};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;
    uint32_t key_size;
    uint32_t state;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_FAIL;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = HSM_MSG_RESUME;
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_GEN_RPMBKEY_CMD, &msg, HSM_GEN_RPMBKEY_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        key_size = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if (key_size != HSM_RPMB_KEY_LEN) {
            ret = TEE_ERROR_OUT_OF_MEMORY;
            goto OUT;
        }
        state = memmove_s((void *)rpmb_key, key_size, buffer_local, key_size);
        if (state != EOK) {
            ret = TEE_ERROR_OUT_OF_MEMORY;
            goto OUT;
        }
    }

OUT:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;
}

TEE_Result TEE_HSM_GenRpmbWrappingKey(uint32_t dev_id, uint8_t *rpmb_wrapping_key)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;
    uint32_t key_size;
    uint32_t state;
    TEE_Result ret;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        tloge("GenRpmbWrappingKey,alloc smem failed!\n");
        return TEE_FAIL;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = HSM_MSG_RESUME;
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_GEN_RPMB_WARPPINGKEY_CMD, &msg, HSM_GEN_RPMB_WARPPINGKEY_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        key_size = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if (key_size != HSM_RPMB_WRAPPING_KEY_LEN) {
            ret = TEE_ERROR_OUT_OF_MEMORY;
            goto OUT;
        }
        state = memmove_s(rpmb_wrapping_key, key_size, buffer_local, key_size);
        if (state != EOK) {
            ret = TEE_ERROR_OUT_OF_MEMORY;
            goto OUT;
        }
    }

OUT:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;
}
