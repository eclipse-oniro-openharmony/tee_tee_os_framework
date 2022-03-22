/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ART service api.
 * Author : c00301810
 * Create: 2020/03/21
 */

#include <art_api.h>
#include <art_public.h>
#include <stdarg.h>
#include <procmgr_ext.h>
#include "securec.h"
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_service_public.h"
#include "mem_ops_ext.h"
#include "tee_inner_uuid.h"

/*
 * @brief      : Allocate an ART counter slot for the caller(Current TA).
 *
 * @param[in]  : void
 * @param[out] : total_counters : total counter number of the allocated slot.
 *
 * @return     : TEE_SUCCESS: successful, others: failed.
 */
TEE_Result TEE_EXT_ARTAllocSlot(uint32_t *total_counters)
{
#ifdef CONFIG_GENERIC_ART
    uint32_t *data = NULL;
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret = TEE_SUCCESS;
    TEE_UUID art_uuid = TEE_SERVICE_ART;

    if (total_counters == NULL) {
        tloge("%s, total_counters is null\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    data = (uint32_t *)tee_alloc_sharemem_aux(&art_uuid, sizeof(uint32_t));
    if (data == NULL) {
        tloge("%s, alloc failed: %x\n", __func__, sizeof(uint32_t));
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    msg.args_data.arg0 = (uintptr_t)data;
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(ART_TASK_NAME, ART_MSG_ALLOC_CMD, &msg, ART_MSG_ALLOC_CMD, &rsp);
    if (rsp.ret != TEE_SUCCESS) {
        tloge("%s, failed: %x\n", __func__, rsp.ret);
        ret = rsp.ret;
    } else {
        *total_counters = *data;
    }

    (void)__SRE_MemFreeShared(data, sizeof(uint32_t));

    return ret;
#else
    (void)total_counters;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

#ifdef CONFIG_GENERIC_ART
/*
 * @brief      : operate ART slot counter.
 *
 * @param[in]  : counter_id : counter ID, from 0 to total_counters-1.
 * @param[in]  : ops : read or increase.
 * @param[out] : counter_value : Counter value.
 *
 * @return     : TEE_SUCCESS: successful; others: failed.
 */
static TEE_Result TEE_EXT_ARTOperateCounter(uint32_t counter_id, uint32_t *counter_value, uint32_t ops)
{
    uint32_t *data = NULL;
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret = TEE_SUCCESS;
    TEE_UUID art_uuid = TEE_SERVICE_ART;

    if (counter_value == NULL) {
        tloge("%s, input null\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    data = (uint32_t *)tee_alloc_sharemem_aux(&art_uuid, sizeof(uint32_t));
    if (data == NULL) {
        tloge("%s, alloc failed: %x\n", __func__, sizeof(uint32_t));
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    msg.args_data.arg0 = counter_id;
    msg.args_data.arg1 = (uintptr_t)data;
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(ART_TASK_NAME, ops, &msg, ops, &rsp);
    if (rsp.ret != TEE_SUCCESS) {
        tloge("%s, failed: %x\n", __func__, rsp.ret);
        ret = rsp.ret;
    } else {
        *counter_value = *data;
    }

    (void)__SRE_MemFreeShared(data, sizeof(uint32_t));

    return ret;
}
#endif

/*
 * @brief      : Read the value of an ART slot counter.
 *
 * @param[in]  : counter_id : counter ID, from 0 to total_counters-1.
 * @param[out] : counter_value : Counter value.
 *
 * @return     : TEE_SUCCESS: successful, others: failed.
 */
TEE_Result TEE_EXT_ARTReadCounter(uint32_t counter_id, uint32_t *counter_value)
{
#ifdef CONFIG_GENERIC_ART
    return TEE_EXT_ARTOperateCounter(counter_id, counter_value, ART_MSG_READ_CMD);
#else
    (void)counter_id;
    (void)counter_value;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief      : Increase the value of an ART slot counter.
 *
 * @param[in]  : counter_id : counter ID, from 0 to total_counters-1.
 * @param[out] : counter_value : Counter value.
 *
 * @return     : TEE_SUCCESS: successful, others: failed.
 */
TEE_Result TEE_EXT_ARTIncreaseCounter(uint32_t counter_id, uint32_t *counter_value)
{
#ifdef CONFIG_GENERIC_ART
    return TEE_EXT_ARTOperateCounter(counter_id, counter_value, ART_MSG_INCREASE_CMD);
#else
    (void)counter_id;
    (void)counter_value;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}
