/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2030. All rights reserved.
 * Description: secure decoder TA main entry
 * Author: lijinwang
 * Create: 2020-03-26
 */

#include "tee_internal_api.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include <tee_ext_api.h>
#include <sre_syscalls_ext.h>
#include <stdint.h>
#include <sre_syscalls_id_ext.h>
#include <hmdrv.h>

enum {
    HIVCODEC_CMD_ID_INIT = 1,
    HIVCODEC_CMD_ID_EXIT,
    HIVCODEC_CMD_ID_SUSPEND,
    HIVCODEC_CMD_ID_RESUME,
    HIVCODEC_CMD_ID_CONTROL,
    HIVCODEC_CMD_ID_RUN_PROCESS,
    HIVCODEC_CMD_ID_GET_IMAGE,
    HIVCODEC_CMD_ID_RELEASE_IMAGE,
    HIVCODEC_CMD_ID_CONFIG_INPUT_BUFFER,
#ifdef VCODEC_ENG_VERSION
    HIVCODEC_CMD_ID_READ_PROC,
    HIVCODEC_CMD_ID_WRITE_PROC,
#endif
    HIVCODEC_CMD_ID_MEM_CPY = 20,
    HIVCODEC_CMD_ID_CFG_MASTER,
#ifdef VCODEC_ENG_VERSION
    HIVCODEC_CMD_ID_MEM_CPY_PROC,
#endif
};

#define MEDIADRMSERVER_NAME   "/system/bin/mediadrmserver"
#define MEDIA_UID 1013
#define CLIENT_CA_MEDIACODEC  "/vendor/bin/hw/android.hardware.media.omx@1.0-service"
#define MEDIA_CODEC_UID 1046
#define ROOT_UID 0
#ifdef VCODEC_ENG_VERSION
#define SAMPLE_OMXVDEC_NAME   "sample_omxvdec"
#define SAMPLE_OMXVENC_NAME   "/vendor/bin/sample_omxvenc"
#endif

#define HI_VCODEC_INVOKE_CODE_A 0x6728661c
#define HI_VCODEC_INVOKE_CODE_B 0x5b9c660c
// unsed to check venc input param
#define NAL_HEAD_LEN  64
#define MAX_COPY_SIZE 320

static TEE_Result ta_server_suspend(uint32_t param_types, TEE_Param *params)
{
    uint64_t args[1] = {0};
    if ((TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_VALUE_OUTPUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(param_types, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(param_types, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        tloge("parameter type check failed , %d\n", __LINE__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[0].value.a = hm_drv_call(SW_SYSCALL_SEC_VDEC_DRV_SUSPEND, args, ARRAY_SIZE(args));

    return TEE_SUCCESS;
}

static TEE_Result ta_server_resume(uint32_t param_types, TEE_Param *params)
{
    uint64_t args[1] = {0};
    if ((TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_VALUE_OUTPUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(param_types, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(param_types, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        tloge("parameter type check failed , %d\n", __LINE__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[0].value.a = hm_drv_call(SW_SYSCALL_SEC_VDEC_DRV_RESUME, args, ARRAY_SIZE(args));
    return TEE_SUCCESS;
}

__attribute__((visibility("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    ret = AddCaller_CA_exec(MEDIADRMSERVER_NAME, MEDIA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CLIENT_CA_MEDIACODEC, MEDIA_CODEC_UID);
    if (ret != TEE_SUCCESS) {
        tloge("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CLIENT_CA_MEDIACODEC, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        tloge("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }

#ifdef VCODEC_ENG_VERSION
    ret = AddCaller_CA_exec(SAMPLE_OMXVDEC_NAME, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        tloge("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }

    ret = AddCaller_CA_exec(SAMPLE_OMXVENC_NAME, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        tloge("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }
#endif

    return ret;
}

__attribute__((visibility("default"))) void TA_DestroyEntryPoint(void) {}

__attribute__((visibility("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4],
    const void **session_context)
{
    S_VAR_NOT_USED(params);
    S_VAR_NOT_USED(session_context);

    if ((TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(param_types, 2) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (TEE_PARAM_TYPE_GET(param_types, 3) != TEE_PARAM_TYPE_MEMREF_INPUT)) {
        SLogError("error out self ta: %s\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

__attribute__((visibility("default"))) void TA_CloseSessionEntryPoint(const void *session_context) {
    S_VAR_NOT_USED(session_context);
}

__attribute__((visibility("default"))) TEE_Result TA_InvokeCommandEntryPoint(const void *session_context,
    uint32_t command_id, uint32_t param_types, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;
    S_VAR_NOT_USED(session_context);
    switch (command_id) {
        case HIVCODEC_CMD_ID_SUSPEND:
            ret = ta_server_suspend(param_types, params);
            break;

        case HIVCODEC_CMD_ID_RESUME:
            ret = ta_server_resume(param_types, params);
            break;
        default:
            ret = TEE_ERROR_BAD_PARAMETERS;
            tlogd("HiVCodec: unkown cmd %d invoked!\n", command_id);
            break;
    }

    return ret;
}
