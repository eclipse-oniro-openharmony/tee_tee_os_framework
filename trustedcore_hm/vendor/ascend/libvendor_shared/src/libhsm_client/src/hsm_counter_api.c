/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: HSM counter api function and algorithm check
 * Author: chenyao
 * Create: 2020-01-08
 * Notes:
 * History: 2020-01-08 chenyao create hsm_kms api functions.
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
#include "hsm_counter_internal.h"

/*
 * @brief     : Hsm Counter init.
 * @param[in] : counter function.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_HSM_CounterInit(uint32_t dev_id, uint8_t *counter_info)

{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;
    uint32_t count_size;
    uint32_t state;

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_READ_DATA;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = HSM_MSG_RESUME;
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_COUNTER_INIT_CMD, &msg, HSM_COUNTER_INIT_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        count_size = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if (count_size > HSM_CLIENT_DDR_LEN) {
            goto HSM_COUNTER_INIT_Ex_Handle;
        }
        state = memcpy_s((void *)counter_info, HSM_CLIENT_DDR_LEN, buffer_local, count_size);
        if (state != EOK) {
            goto HSM_COUNTER_INIT_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_COUNTER_INIT_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * @brief     : Hsm Counter create.
 * @param[in] : counter create function.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_HSM_CounterCreate(uint32_t dev_id, HSM_COUNT_CREATE_INFO *count_create_info)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;
    uint32_t size0;
    uint32_t size1;
    uint32_t state;

    ret = counter_create_para_check(count_create_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = counter_create_request_sharemem(&buffer_local, &buffer_size, count_create_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = ((uint64_t)(HSM_IV_SIZE +
        count_create_info->counter_auth_len) << HSM_CONST_SHIFT_32) | (uint64_t)(HSM_COUNTER_SIZE);
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_COUNTER_CREATE_CMD, &msg, HSM_COUNTER_CREATE_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        size1 = (uint32_t)(rsp.msg.args_data.arg2);
        if ((size0 > HSM_COUNTER_ID_SIZE) || (size1 > HSM_COUNTER_SIZE)) {
            goto HSM_COUNTER_CREATE_Ex_Handle;
        }
        state = memmove_s(count_create_info->counter_id, size0, buffer_local, size0);
        if (state != EOK) {
            goto HSM_COUNTER_CREATE_Ex_Handle;
        }
        state = memmove_s(count_create_info->counter_info, size1, buffer_local + size0, size1);
        if (state != EOK) {
            goto HSM_COUNTER_CREATE_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_COUNTER_CREATE_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * @brief     : Hsm Counter read.
 * @param[in] : counter read function.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_HSM_CounterRead(uint32_t dev_id, HSM_COUNT_READ_INFO *count_read_info)

{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;
    uint32_t size0;
    uint32_t state;

    ret = counter_read_para_check(count_read_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = counter_read_request_sharemem(&buffer_local, &buffer_size, count_read_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = ((uint64_t)(HSM_COUNTER_ID_SIZE) << HSM_CONST_SHIFT_32) | (uint64_t)(HSM_COUNTER_SIZE);
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_COUNTER_READ_CMD, &msg, HSM_COUNTER_READ_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if (size0 > HSM_COUNTER_VALUE_SIZE) {
            goto HSM_COUNTER_READ_Ex_Handle;
        }
        state = memmove_s(count_read_info->count_value, size0, buffer_local, size0);
        if (state != EOK) {
            goto HSM_COUNTER_READ_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_COUNTER_READ_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * @brief     : Hsm Counter delete.
 * @param[in] : counter deete function.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_HSM_CounterDelete(uint32_t dev_id, HSM_COUNT_DELETE_INFO *count_delete_info)

{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;
    uint32_t size0;
    uint32_t state;

    ret = counter_delete_para_check(count_delete_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = counter_delete_request_sharemem(&buffer_local, &buffer_size, count_delete_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = ((uint64_t)(HSM_COUNTER_ID_SIZE) << HSM_CONST_SHIFT_32) |
        (uint64_t)(HSM_IV_SIZE + count_delete_info->counter_auth_len);
    msg.args_data.arg3 = ((uint64_t)(HSM_COUNTER_SIZE) << HSM_CONST_SHIFT_32) | HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_COUNTER_DELETE_CMD, &msg, HSM_COUNTER_DELETE_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        if (size0 > HSM_COUNTER_SIZE) {
            goto HSM_COUNTER_DELETE_Ex_Handle;
        }
        state = memmove_s(count_delete_info->counter_info, size0, buffer_local, size0);
        if (state != EOK) {
            goto HSM_COUNTER_DELETE_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_COUNTER_DELETE_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * @brief     : Hsm Counter inc.
 * @param[in] : counter inc function.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_HSM_CounterInc(uint32_t dev_id, HSM_COUNT_INC_INFO *count_inc_info)

{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;
    uint32_t size0;
    uint32_t size1;
    uint32_t state;

    ret = counter_inc_para_check(count_inc_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = counter_inc_request_sharemem(&buffer_local, &buffer_size, count_inc_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = ((uint64_t)(HSM_COUNTER_ID_SIZE) << HSM_CONST_SHIFT_32) |
        (uint64_t)(HSM_IV_SIZE + count_inc_info->counter_auth_len);
    msg.args_data.arg3 = ((uint64_t)(HSM_COUNTER_VALUE_SIZE) << HSM_CONST_SHIFT_32) | (uint64_t)(HSM_COUNTER_SIZE);
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_COUNTER_INC_CMD, &msg, HSM_COUNTER_INC_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        size0 = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        size1 = (uint32_t)(rsp.msg.args_data.arg2);
        if ((size0 > HSM_COUNTER_VALUE_SIZE) || (size1 > HSM_COUNTER_SIZE)) {
            goto HSM_COUNTER_INC_Ex_Handle;
        }
        state = memmove_s(count_inc_info->counter_value, size0, buffer_local, size0);
        if (state != EOK) {
            goto HSM_COUNTER_INC_Ex_Handle;
        }
        state = memmove_s(count_inc_info->counter_info, size1, buffer_local + size0, size1);
        if (state != EOK) {
            goto HSM_COUNTER_INC_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_COUNTER_INC_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * @brief     : Hsm Algorithm inspection.
 * @param[in] : counter function.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_HSM_AlgCheck(uint32_t dev_id, uint32_t *hsm_accelerator_status, uint32_t hsm_status_len)

{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint8_t *buffer_local = NULL;
    uint32_t buffer_size = HSM_CLIENT_DDR_LEN;
    uint32_t ac_status_len;
    uint32_t state;

    if ((hsm_accelerator_status == NULL) || (hsm_status_len > HSM_AC_STATUS_CHECK_LEN)) {
        tloge("wrong parameter in algcheck\n");
        return TEE_ERROR_READ_DATA;
    }

    buffer_local = (uint8_t *)(uintptr_t)tee_alloc_sharemem_aux(&g_hsm_uuid, HSM_CLIENT_DDR_LEN);
    if (buffer_local == NULL) {
        return TEE_ERROR_READ_DATA;
    }

    msg.args_data.arg0 = (uint64_t)(uintptr_t)(buffer_local);
    msg.args_data.arg1 = (uint64_t)(buffer_size);
    msg.args_data.arg2 = HSM_MSG_RESUME;
    msg.args_data.arg3 = HSM_MSG_RESUME;
    msg.args_data.arg4 = HSM_MSG_RESUME;
    msg.args_data.arg5 = HSM_MSG_RESUME;
    msg.args_data.arg6 = (uint64_t)dev_id;
    msg.args_data.arg7 = HSM_MSG_RESUME;

    tee_common_ipc_proc_cmd(HSM_TASK_NAME, HSM_ALG_CHECK_CMD, &msg, HSM_ALG_CHECK_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        ac_status_len = (uint32_t)(rsp.msg.args_data.arg2 >> HSM_CONST_SHIFT_32);
        state = memmove_s(hsm_accelerator_status, hsm_status_len, buffer_local, ac_status_len);
        if (state != EOK) {
            goto HSM_ALG_CHECK_Ex_Handle;
        }
    }

    __SRE_MemFreeShared(buffer_local, buffer_size);
    return ret;

HSM_ALG_CHECK_Ex_Handle:
    __SRE_MemFreeShared(buffer_local, buffer_size);
    return TEE_ERROR_OUT_OF_MEMORY;
}
