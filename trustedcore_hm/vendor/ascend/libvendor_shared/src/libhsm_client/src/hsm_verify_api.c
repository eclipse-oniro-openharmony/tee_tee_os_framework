/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: HSM verify api
 * Author: chenyao
 * Create: 2020-05-21
 * Notes:
 * History:
 */
#include <stdarg.h>
#include "securec.h"
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_obj.h"
#include "securec.h"
#include "string.h"
#include "hsm_public.h"
#include "hsm_verify_api.h"
#include "tee_service_public.h"
#include "hsm_update_lib_api.h"
#include "mem_ops_ext.h"

TEE_Result TEE_HSM_SOC_VERIFY(uint32_t dev_id, uint64_t image_addr, uint32_t image_len, uint32_t img_id)
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

    if (memmove_s(buffer_local, IMG_ADDR_SIZE, &image_addr, IMG_ADDR_SIZE)) {
        goto HSM_SOC_VERIFY_Ex_Handle;
    }

    if (memmove_s(buffer_local + IMG_ADDR_SIZE, IMG_LEN_SIZE, &image_len, IMG_LEN_SIZE)) {
        goto HSM_SOC_VERIFY_Ex_Handle;
    }

    if (memmove_s(buffer_local + IMG_ADDR_SIZE + IMG_LEN_SIZE, IMG_ID_SIZE, &img_id, IMG_ID_SIZE)) {
        goto HSM_SOC_VERIFY_Ex_Handle;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)IMG_ADDR_SIZE) << HSM_CONST_SHIFT_32) | (uint64_t)(IMG_LEN_SIZE);
    msg.args_data.arg3 = (((uint64_t)IMG_ID_SIZE) << HSM_CONST_SHIFT_32) | HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_SOC_VERIFY_CMD, &msg, HSM_SOC_VERIFY_CMD, &rsp);

    ret = rsp.ret;

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_SOC_VERIFY_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result TEE_HSM_Hboot1a_Trans(uint32_t dev_id)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;
    uint32_t image_addr = 0x9A9A4B4B;
    uint32_t image_len = 0xABAB55AA;

    ret = lib_hboot1a_addr_get(dev_id, &image_addr, &image_len);
    if (ret != TEE_SUCCESS) {
        tloge("get hboot1_a addr fail\n");
        return TEE_SUCCESS;
    }

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(buffer_local, IMG_ADDR_SIZE, &image_addr, IMG_ADDR_SIZE) != EOK) {
        goto HSM_SOC_VERIFY_Ex_Handle;
    }

    if (memmove_s(buffer_local + IMG_ADDR_SIZE, IMG_LEN_SIZE, &image_len, IMG_LEN_SIZE) != EOK) {
        goto HSM_SOC_VERIFY_Ex_Handle;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)IMG_ADDR_SIZE) << HSM_CONST_SHIFT_32) | (uint64_t)(IMG_LEN_SIZE);
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_HBOOT1A_TRANS_CMD, &msg, HSM_HBOOT1A_TRANS_CMD, &rsp);

    ret = rsp.ret;

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_SOC_VERIFY_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}
