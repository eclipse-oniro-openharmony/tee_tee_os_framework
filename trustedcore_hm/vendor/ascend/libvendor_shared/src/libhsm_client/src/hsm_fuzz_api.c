/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: HSM fuzz service test client api
 * Author: chenyao
 * Create: 2021-06-17
 * Notes:
 * History:
 */
#include <stdarg.h>
#include "securec.h"
#include "ta_framework.h"
#include "tee_log.h"
#include "hsm_public.h"
#include "hsm_fuzz_api.h"
#include "tee_service_public.h"

static TEE_Result service_fuzz_para_check(uint8_t *service_msg, uint32_t msg_size,
    uint8_t *service_data, uint32_t data_size)
{
    if ((service_msg == NULL) || (service_data == NULL)) {
        return TEE_ERROR_NO_DATA;
    }

    if ((msg_size > sizeof(FUZZ_SERVICE_S)) || (data_size > HSM_CLIENT_DDR_LEN)) {
        return TEE_ERROR_NO_DATA;
    }

    return TEE_SUCCESS;
}

TEE_Result TEE_HSM_SERVICE_FUZZ(uint8_t *service_msg, uint32_t msg_size, uint8_t *service_data, uint32_t data_size)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;
    FUZZ_SERVICE_S *service_fuzz = (FUZZ_SERVICE_S *)(uintptr_t)service_msg;

    ret =-service_fuzz_para_check(service_msg, msg_size, service_data, data_size);
    if (ret != TEE_SUCCESS) {
        tloge("service fuzz para check fail");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        tloge("memory alloc in fuzz service fail");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(buffer_local, HSM_CLIENT_DDR_LEN, service_data, data_size) != 0) {
        tloge("cpy service data fuzz service fail");
        goto HSM_SERVICE_FUZZ_Ex_Handle;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = (((uint64_t)service_fuzz->param_len_0) << HSM_CONST_SHIFT_32) |
        (uint64_t)(service_fuzz->param_len_1);
    msg.args_data.arg3 = (((uint64_t)service_fuzz->param_len_2) << HSM_CONST_SHIFT_32) |
        (uint64_t)(service_fuzz->param_len_3);
    msg.args_data.arg4 = (((uint64_t)service_fuzz->param_len_4) << HSM_CONST_SHIFT_32) |
        (uint64_t)(service_fuzz->param_len_5);
    msg.args_data.arg5 = (((uint64_t)service_fuzz->param_len_6) << HSM_CONST_SHIFT_32) |
        (uint64_t)(service_fuzz->param_len_7);
    msg.args_data.arg6 = HSM_MSG_RESUME;
    msg.args_data.arg7 = (((uint64_t)service_fuzz->cmd) << HSM_CONST_SHIFT_32) |
        (uint64_t)(service_fuzz->ddr_para_num);

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_SERVICE_FUZZ_CMD, &msg, HSM_SERVICE_FUZZ_CMD, &rsp);

    if (memmove_s(service_data, data_size, buffer_local, data_size) != 0) {
        tloge("cpy buffer data fuzz service fail");
        goto HSM_SERVICE_FUZZ_Ex_Handle;
    }

    ret = rsp.ret;

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_SERVICE_FUZZ_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}
