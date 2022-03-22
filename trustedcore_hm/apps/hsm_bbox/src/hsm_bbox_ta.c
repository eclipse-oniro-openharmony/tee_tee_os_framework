/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: hsm heartbeat ca
 * Author: chenyao
 * Create: 2020-04-30
 */

#include "tee_defines.h"
#include "tee_ext_api.h"
#include "tee_log.h"

#include "securec.h"

#include "hsm_kms_api.h"
#include "hsm_kms_internal.h"
#include "hsm_ta_public.h"
#include "hsm_bbox_ta.h"
#include "hsm_counter_api.h"
#include "hsm_pg_info_lib_api.h"
#include "hsm_fuzz_api.h"
#include "hsm_update_lib_api.h"

static uint32_t g_dev_id_max = 0;

STATIC TEE_Result bbox_dev_id_verify(uint32_t dev_id)
{
    if (dev_id > g_dev_id_max) {
        SLogError("dev id is invalid, 0x%x.\n", dev_id);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

STATIC TEE_Result tee_hsm_check_static(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;
    uint32_t state = 0;
    uint64_t tv_sec;
    uint64_t tv_usec;
    uint32_t dev_id;
    HSM_BBOX_INFO hsm_bbox_info;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    dev_id = params[HSM_INDEX3].value.a;

    ret = bbox_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    hsm_bbox_info.state = &state;
    tv_sec = COMBINE_HI_32LO(params[1].value.a, params[1].value.b);
    tv_usec = COMBINE_HI_32LO(params[HSM_INDEX2].value.a, params[HSM_INDEX2].value.b);

    ret = TEE_HSM_Bbox(dev_id, &hsm_bbox_info, tv_sec, tv_usec);
    if (ret != TEE_SUCCESS) {
        SLogError("HSM bbox execute failed, 0x%x\n", ret);
        return ret;
    }

    params[0].value.a = state;

    return TEE_SUCCESS;
}

STATIC TEE_Result tee_hsm_notify(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;
    uint32_t dev_id;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    dev_id = params[0].value.a;

    ret = bbox_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = TEE_HSM_notify_prereset(dev_id);
    if (ret != TEE_SUCCESS) {
        SLogError("HSM notify prereset failed, 0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC TEE_Result tee_hsm_ac_check(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;
    uint32_t dev_id;
    uint32_t accelerator_status = 0;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INOUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    dev_id = params[1].value.a;

    ret = bbox_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = TEE_HSM_AlgCheck(dev_id, &accelerator_status, params[0].value.b);
    if (ret != TEE_SUCCESS) {
        SLogError("HSM accelerator check failed, 0x%x\n", ret);
        return ret;
    }

    params[0].value.a = accelerator_status;

    return TEE_SUCCESS;
}

STATIC TEE_Result tee_hsm_pg_info_get(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;
    uint32_t dev_id, module, data, size;
    uint64_t *buffer = NULL;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    dev_id = params[0].value.a;
    module = params[1].value.a;
    data = params[1].value.b;
    buffer = (uint64_t *)(uintptr_t)params[HSM_INDEX2].memref.buffer;
    size = params[HSM_INDEX2].memref.size;

    ret = bbox_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if ((module > MODULE_TYPE_MAX) || (data > DATA_TYPE_MAX) || (buffer == NULL) ||
        (size != READ_PG_INFO_LEN)) {
        SLogError("Bad command parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = (TEE_Result)lib_pg_info_read(dev_id, module, data, buffer);
    if (ret != TEE_SUCCESS) {
        SLogError("HSM pg info read failed, ret is : %x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t tee_hsm_service_fuzz(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_MEMREF_INOUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[HSM_INDEX0].memref.size == 0 ||
        params[HSM_INDEX1].memref.size == 0) {
        SLogError("Bad expected parameter types.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = TEE_HSM_SERVICE_FUZZ(params[HSM_INDEX0].memref.buffer, params[HSM_INDEX0].memref.size,
                               params[HSM_INDEX1].memref.buffer, params[HSM_INDEX1].memref.size);
    if (ret != TEE_SUCCESS) {
        SLogError("HSM service fuzz failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("HSM service fuzz succeed\n");

    return TEE_SUCCESS;
}

/* ---------------------------------------------------------------
 *   Trusted Application Entry Points
 * ---------------------------------------------------------------
 *  Function TA_CreateEntryPoint
 *  Description
 *  The function TA_CreateEntryPoint is the Trusted Application's
 *  constructor, which the Framework calls when it creates a new
 *  instance of the Trusted Application.
 */
__attribute__((visibility ("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    tlogd("Hello heartbeat TA.\n");

    ret = AddCaller_TA_all();
    if (ret != TEE_SUCCESS) {
        tloge("add TA caller failed, 0x%x.\n", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(ROOTSCAN_HAM, ROOTSCAN_HSM_UID);
    if (ret != TEE_SUCCESS) {
        tloge("add caller HSM failed, 0x%x.\n", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(ROOTSCAN_HAM, HWHIAIUSER_UID);
    if (ret != TEE_SUCCESS) {
        tloge("add caller DMP failed, 0x%x.\n", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(HSM_FUZZ_CA, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add fuzz ca error, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

/**
 *  Function TA_OpenSessionEntryPoint
 *  Description
 *    The Framework calls the function TA_OpenSessionEntryPoint
 *    when a client requests to open a session with the Trusted Application.
 *    The open session request may result in a new Trusted Application instance
 *    being created.
 */
__attribute__((visibility ("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
    TEE_Param params[OPEN_SESSION_PARA_NUM], void **sessionContext)
{
    TEE_Result ret;
    uint32_t dev_num = 1;

    (void)paramTypes; /* -Wunused-parameter */
    (void)params; /* -Wunused-parameter */
    (void)sessionContext; /* -Wunused-parameter */

    ret = lib_get_device_num(&dev_num);
    if (ret != TEE_SUCCESS) {
        SLogError("get device num fail, 0x%x\n", ret);
        return TEE_ERROR_BAD_STATE;
    }

    g_dev_id_max = (dev_num > 1) ? 1 : 0;

    return TEE_SUCCESS;
}

/**
 *  Function TA_InvokeCommandEntryPoint
 *  Description
 *    The Framework calls this function when the client invokes a command
 *    within the given session.
 */
__attribute__((visibility ("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext,
    uint32_t cmd_id, uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    (void)sessionContext; /* -Wunused-parameter */

    switch (cmd_id) {
        case HSM_CHECK_STATE_CMD:
            return tee_hsm_check_static(paramTypes, params);
        case HSM_NOTIFY_PRERESET_TA_CMD:
            return tee_hsm_notify(paramTypes, params);
        case HSM_ACCELERATOR_CHECK_CMD:
            return tee_hsm_ac_check(paramTypes, params);
        case HSM_PG_FG_INFO_CMD:
            return tee_hsm_pg_info_get(paramTypes, params);
        case TEE_HSM_SRV_FUZZ:
            return tee_hsm_service_fuzz(paramTypes, params);
        default:
            SLogError("Unknown CMD ID: %x", cmd_id);
            break;
    }

    return TEE_ERROR_NOT_SUPPORTED;
}

/**
 *  Function TA_CloseSessionEntryPoint
 *  Description
 *    The Framework calls this function to close a client session.
 *    During the call to this function the implementation can use
 *    any session functions.
 */
__attribute__((visibility ("default"))) void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext; /* -Wunused-parameter */
}
