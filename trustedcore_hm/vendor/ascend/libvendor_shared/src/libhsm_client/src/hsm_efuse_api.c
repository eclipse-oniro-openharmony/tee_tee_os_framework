/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: HSM counter api function and algorithm check
 * Author: chenyao
 * Create: 2020-01-08
 * Notes:
 * History: 2020-01-08 chenyao create efuse api functions.
            2020-06-24 chenyao add rim and nvcnt update functions.
 */
#include <stdarg.h>
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_obj.h"
#include "securec.h"
#include "string.h"
#include "hsm_efuse_api.h"
#include "efuse_api.h"
#include "hsm_public.h"
#include "tee_service_public.h"
#include "mem_ops_ext.h"

TEE_Result TEE_HSM_RIM_UpDate(uint32_t dev_id, uint8_t *rim_info, uint32_t rim_size)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    if (rim_size != HSM_RIM_MAX_SIZE) {
        tloge("rim info size is wrong\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        tloge("buffer is null, please realloc\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(buffer_local, rim_size, rim_info, HSM_RIM_MAX_SIZE) != EOK) {
        tloge("memmove rim info fail\n");
        goto HSM_RIM_UPDATE_Ex_Handle;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)HSM_RIM_INFO_SIZE) << HSM_CONST_SHIFT_32) | (uint64_t)(HSM_ROOT_KEY_SIZE);
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_RIM_VALUE_UPDATE_CMD, &msg, HSM_RIM_VALUE_UPDATE_CMD, &rsp);

    ret = rsp.ret;

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_RIM_UPDATE_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_Power_On(uint32_t dev_id)
{
    tee_service_ipc_msg_rsp rsp = {0};
    tee_service_ipc_msg msg = {{0}};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        tloge("hsm power on, alloc smem failed!\n");
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

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_EFUSE_POWER_ON_CMD, &msg, HSM_EFUSE_POWER_ON_CMD, &rsp);

    ret = rsp.ret;

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;
}

TEE_Result TEE_HSM_Power_Off(uint32_t dev_id)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        tloge("hsm power off, alloc smem failed!\n");
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

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_EFUSE_POWER_OFF_CMD, &msg, HSM_EFUSE_POWER_OFF_CMD, &rsp);

    ret = rsp.ret;

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;
}
