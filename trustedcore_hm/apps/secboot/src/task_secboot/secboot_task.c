/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2019. All rights reserved.
 * Description: secboot TA
 * Create: 2013/5/16
 */

#include "secboot_verify.h"
#include "secboot_load_modem_teeos.h"
#include "secboot_modem_call.h"
#include "tee_ext_api.h"
#include "tee_internal_api.h"
#include "tee_log.h"
#include "tee_ext_api.h"
#include "sre_syscall.h"
#include "ccmgr_ops_ext.h"

#define ROOT_UID 0
#define SEC_BOOT "sec_boot"
#define UNUSED(x) ((void)(x))

__attribute__((visibility("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    ret = (TEE_Result)AddCaller_CA_exec(SEC_BOOT, ROOT_UID);

    tlogd("secboot_task: succeed to CreateEntryPoint\n");
    return ret;
}

__attribute__((visibility("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t paramtypes,
    TEE_Param params[PARAMS_COUNT], void **sessioncontext)
{
    TEE_Result ret = TEE_SUCCESS;

    UNUSED(paramtypes);
    UNUSED(params);
    UNUSED(sessioncontext);
    return ret;
}

__attribute__((visibility("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t cmd_id,
    uint32_t paramtypes, TEE_Param params[PARAMS_COUNT])
{
    INT32 res;
    TEE_Result ret;
    UNUSED(session_context);

    res = __CC_DX_power_on();
    if (res != 0) {
        tloge("CC DX power on failed\n");
        return TEE_ERROR_GENERIC;
    }

    tlogd("secboot_task:invoke command begin, cmd_id=0x%x\n", cmd_id);
    switch (cmd_id) {
        case SECBOOT_CMD_ID_RESET_IMAGE:
            ret = (TEE_Result)seb_reset_image(paramtypes, params);
            break;
        case SECBOOT_CMD_ID_COPY_VRL_TYPE:
            ret = (TEE_Result)seb_copy_vrl_type(paramtypes, params);
            break;
        case SECBOOT_CMD_ID_COPY_DATA_TYPE:
            ret = (TEE_Result)seb_copy_soc_data_type(paramtypes, params);
            break;
        case SECBOOT_CMD_ID_VERIFY_DATA_TYPE:
            ret = (TEE_Result)seb_verify_soc_data_type(paramtypes, params);
            break;
        case SECBOOT_CMD_ID_COPY_IMG_TYPE:
            ret = (TEE_Result)seb_copy_soc_img_type(paramtypes, params);
            break;
        case SECBOOT_CMD_ID_BSP_MODEM_CALL:
            ret = (TEE_Result)seb_bsp_modem_call(paramtypes, params);
            break;
        case SECBOOT_CMD_ID_BSP_MODEM_CALL_EXT:
            ret = (TEE_Result)seb_bsp_modem_call_ext(paramtypes, params);
            break;
        case SECBOOT_CMD_ID_GET_RNG_NUM:
            ret = seb_get_rng_num(paramtypes, params);
            break;
        case SECBOOT_CMD_ID_BSP_LOAD_MODEM_TEEOS:
            ret = seb_modem_load_modem_teeos(paramtypes, params);
            break;
        case SECBOOT_CMD_ID_BSP_UNLOAD_MODEM_TEEOS:
            ret = seb_modem_unload_modem_teeos(paramtypes, params);
            break;
        default:
            tloge("cmd id is not valid: cmd is 0x%x\n", cmd_id);
            ret = TEE_ERROR_GENERIC;
            break;
    }

    res = __CC_DX_power_down();
    if (res != 0) {
        tloge("CC DX power down failed\n");
        return TEE_ERROR_GENERIC;
    }
    tlogd("secboot_task:invoke command end ret = 0x%x\n", ret);
    return ret;
}

__attribute__((visibility("default"))) void TA_CloseSessionEntryPoint(void *session_context)
{
    UNUSED(session_context);
    tlogd("secboot_task:Succeed to CloseSession\n");
}

__attribute__((visibility("default"))) void TA_DestroyEntryPoint(void)
{
    tlogd("secboot_task:Succeed to DestoryEntryPoint\n");
}
