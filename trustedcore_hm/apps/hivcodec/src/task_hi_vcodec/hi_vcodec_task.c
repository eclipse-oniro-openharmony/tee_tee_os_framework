/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: added for hm-teeos
 * Author: hanxuanwei
 * Create: 2018-05-21
 */

#include "tee_log.h"
#include "tee_mem_mgmt_api.h"
#include "tee_time_api.h"
#include "tee_trusted_storage_api.h"
#include "tee_ext_api.h"

#include <sre_syscalls_ext.h>

#define HI_VCODEC_INVOKE_CODE_A 0x6728661c
#define HI_VCODEC_INVOKE_CODE_B 0x5b9c660c

enum {
    HIVCODEC_CMD_ID_INIT = 1,
    HIVCODEC_CMD_ID_EXIT,
    HIVCODEC_CMD_ID_SUSPEND,
    HIVCODEC_CMD_ID_RESUME,
    HIVCODEC_CMD_ID_CONTROL,
    HIVCODEC_CMD_ID_RUN_PROCESS,
    HIVCODEC_CMD_ID_GET_IMAGE,
    HIVCODEC_CMD_ID_RELEASE_IMAGE,
#ifdef VCODEC_ENG_VERSION
    HIVCODEC_CMD_ID_READ_PROC,
    HIVCODEC_CMD_ID_WRITE_PROC,
#endif
};

static TEE_Result TaVdecInit(uint32_t paramTypes, TEE_Param params[4])
{
    if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_VALUE_OUTPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[2].value.a = (unsigned int)__SEC_VDEC_Init((uint32_t *)params[0].memref.buffer, params[0].memref.size,
                                                      (uint32_t *)params[1].memref.buffer, params[1].memref.size);
    return TEE_SUCCESS;
}

static TEE_Result TaVdecExit(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[0].value.a = (unsigned int)__SEC_VDEC_Exit(params[0].value.a);
    return TEE_SUCCESS;
}

static TEE_Result TaVdecSuspend(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_OUTPUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[0].value.a = (unsigned int)__SEC_VDEC_Suspend();
    return TEE_SUCCESS;
}

static TEE_Result TaVdecResume(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_OUTPUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[0].value.a = (unsigned int)__SEC_VDEC_Resume();
    return TEE_SUCCESS;
}

static TEE_Result TaVdecControl(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (TEE_PARAM_TYPE_GET(paramTypes, 1) == TEE_PARAM_TYPE_MEMREF_INOUT) {
        params[0].value.a = (unsigned int)__SEC_VDEC_Control((int)params[0].value.a, params[0].value.b,
                                                             (uint32_t *)params[1].memref.buffer,
                                                             params[1].memref.size);
    } else if (TEE_PARAM_TYPE_GET(paramTypes, 1) == TEE_PARAM_TYPE_NONE) {
        params[0].value.a = (unsigned int)__SEC_VDEC_Control((int)params[0].value.a, params[0].value.b, NULL, 0);
    } else {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result TaVdecRunProcess(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[0].value.a = (unsigned int)__SEC_VDEC_RunProcess(params[0].value.a, params[0].value.b);
    return TEE_SUCCESS;
}

static TEE_Result TaVdecGetChanImage(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INOUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[0].value.a =
        (unsigned int)__SEC_VDEC_GetChanImage((int)params[0].value.a, (unsigned int *)params[1].memref.buffer);
    return TEE_SUCCESS;
}

static TEE_Result TaVdecReleaseChanImage(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[0].value.a =
        (unsigned int)__SEC_VDEC_ReleaseChanImage((int)params[0].value.a, params[0].value.b, params[1].value.a);
    return TEE_SUCCESS;
}

#ifdef VCODEC_ENG_VERSION
static TEE_Result TaVdecReadProc(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[0].value.a = (unsigned int)__SEC_VDEC_ReadProc(params[0].value.a, params[0].value.b, (int)params[1].value.a);
    return TEE_SUCCESS;
}

static TEE_Result TaVdecWriteProc(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[0].value.a = (unsigned int)__SEC_VDEC_WriteProc(params[0].value.a, (int)params[0].value.b);
    return TEE_SUCCESS;
}
#endif

__attribute__((visibility ("default"))) TEE_Result TA_InvokeCommandEntryPoint(const void *sessionContext,
    uint32_t commandId, uint32_t paramTypes, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;
    S_VAR_NOT_USED(sessionContext);

    switch (commandId) {
        case HIVCODEC_CMD_ID_INIT:
            ret = TaVdecInit(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_EXIT:
            ret = TaVdecExit(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_SUSPEND:
            ret = TaVdecSuspend(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_RESUME:
            ret = TaVdecResume(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_CONTROL:
            ret = TaVdecControl(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_RUN_PROCESS:
            ret = TaVdecRunProcess(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_GET_IMAGE:
            ret = TaVdecGetChanImage(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_RELEASE_IMAGE:
            ret = TaVdecReleaseChanImage(paramTypes, params);
            break;

#ifdef VCODEC_ENG_VERSION
        case HIVCODEC_CMD_ID_READ_PROC:
            ret = TaVdecReadProc(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_WRITE_PROC:
            ret = TaVdecWriteProc(paramTypes, params);
            break;
#endif
        default:
            ret = TEE_ERROR_BAD_PARAMETERS;
            tlogd("HiVCodec: unkown cmd %d invoked!\n", commandId);
            break;
    }

    return  ret;
}

#define MEDIADRMSERVER_NAME     "/system/bin/mediadrmserver"
#define MEDIA_UID               1013
#define CLIENT_CA_MEDIACODEC    "/vendor/bin/hw/android.hardware.media.omx@1.0-service"
#define MEDIA_CODEC_UID         1046
#ifdef VCODEC_ENG_VERSION
#define SAMPLE_OMXVDEC_NAME     "sample_omxvdec"
#define ROOT_UID                0
#endif

__attribute__((visibility ("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    ret = AddCaller_CA_exec(MEDIADRMSERVER_NAME, MEDIA_UID);
    if (ret != TEE_SUCCESS) {
        tlogd("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CLIENT_CA_MEDIACODEC, MEDIA_CODEC_UID);
    if (ret != TEE_SUCCESS) {
        tlogd("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }

#ifdef VCODEC_ENG_VERSION
    ret = AddCaller_CA_exec(SAMPLE_OMXVDEC_NAME, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        tlogd("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }
#endif

    return ret;
}

__attribute__((visibility ("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
    TEE_Param params[4], const void **sessionContext)
{
    S_VAR_NOT_USED(params);
    S_VAR_NOT_USED(sessionContext);

    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_NONE) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_MEMREF_INPUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

__attribute__((visibility ("default"))) void TA_CloseSessionEntryPoint(const void *sessionContext)
{
    S_VAR_NOT_USED(sessionContext);
}

__attribute__((visibility ("default"))) void TA_DestroyEntryPoint(void)
{
}

