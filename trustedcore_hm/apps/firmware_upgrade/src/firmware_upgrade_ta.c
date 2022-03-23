/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2021. All rights reserved.
 * Description: firmware upgrade ta file
 * Author: chenyao
 * Create: 2018-04-03
 */
#include "tee_defines.h"
#include "tee_ext_api.h"
#include "tee_log.h"
#include "securec.h"

#include "hsm_ta_public.h"
#include "hsm_update_lib_api.h"
#include "firmware_upgrade_ta.h"
#include "firmware_upgrade_api.h"
#include "firmware_upgrade_ta_api.h"

uint32_t g_dev_id_max = 0;

static tee_upgrade_cmd g_upgrade_cmd_tbl[] = {
    {HSM_SEC_IMG_VERIFY_CMD, tee_sec_img_verify},
    {HSM_SEC_IMG_UPDATE_CMD, tee_sec_img_update},
    {HSM_SEC_IMG_UPDATE_FINISH_CMD, tee_sec_update_finish},
    {HSM_SEC_IMG_SYNC_AND_EFUSE_UPDATE, tee_sec_img_sync_entry},
    {HSM_SEC_RIM_UPDATE, tee_sec_rim_update},
    {HSM_SEC_VERSION_GET, tee_sec_img_version_get},
    {HSM_SEC_COUNT_GET, tee_sec_img_count_get},
    {HSM_SEC_INFO_GET, tee_sec_img_info_get},
    {HSM_SEC_UFS_CNT_READ, tee_sec_ufs_cnt_read},
    {HSM_SEC_UFS_CNT_WRITE, tee_sec_ufs_cnt_write},
    {HSM_SEC_CLEAR_CNT, tee_sec_cnt_clear},
    {HSM_SEC_SYNC_BEFORE_UPGRADE, tee_sec_img_sync_before_upgrade},
    {HSM_SEC_FLASH_GET_CMDLINED, tee_get_cmdline_info},
    {SOC_GET_EFUSE_NVCNT, tee_get_efuse_nvcnt},
    {HSM_SEC_RESET_RECOVERT_BOOT_CNT, tee_sec_recovery_cnt_reset},
};

/*
 *  Function TA_CreateEntryPoint
 *  Description:
 *    The function TA_CreateEntryPoint is the Trusted Application's
 *    constructor, which the Framework calls when it creates a new
 *    instance of the Trusted Application.
 */
__attribute__((visibility ("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    tlogd("Hello hsm firmware upgrade.\n");

    ret = AddCaller_TA_all();
    if (ret != TEE_SUCCESS) {
        SLogError("fimware addcaller ta failed, 0x%x.\n", ret);
        return ret;
    }

    tlogd("fimware addcaller ta success.\n");

    ret = AddCaller_CA_exec(FIRMWARE_UPGRADE_CA, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add root auth error, 0x%x.", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(FIRMWARE_UPGRADE_CA, HWHIAIUSER_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add hwhiaiuser auth error, 0x%x.", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(HSM_FUZZ_CA, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add fuzz ca error, 0x%x.", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

/**
 *  Function TA_OpenSessionEntryPoint
 *  Description:
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

    SLogTrace("---- TA_OpenSessionEntryPoint -------- ");

    (void)paramTypes;  /* -Wunused-parameter */
    (void)params;  /* -Wunused-parameter */
    (void)sessionContext;  /* -Wunused-parameter */

    ret = lib_get_device_num(&dev_num);
    if (ret != TEE_SUCCESS) {
        SLogError("get device num fail, 0x%x.\n", ret);
        return ret;
    }

    g_dev_id_max = (dev_num > 1) ? 1 : 0;

    return TEE_SUCCESS;
}

/**
 *  Function TA_InvokeCommandEntryPoint
 *  Description:
 *    The Framework calls this function when the client invokes a command
 *    within the given session.
 */
__attribute__((visibility ("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext,
    uint32_t cmd_id, uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    uint32_t loop_times = sizeof(g_upgrade_cmd_tbl) / sizeof(tee_upgrade_cmd);
    uint32_t i;

    (void)sessionContext;  /* -Wunused-parameter */

    SLogTrace("---- TA_InvokeCommandEntryPoint ----------- ");

    for (i = 0; i < loop_times; i++) {
        if (g_upgrade_cmd_tbl[i].cmd == cmd_id) {
            break;
        }
    }

    if (i == loop_times) {
        SLogError("Unknown cmd id : 0x%x.\n", cmd_id);
        return TEE_ERROR_NOT_SUPPORTED;
    }

    return (*g_upgrade_cmd_tbl[i].fn)(paramTypes, params);
}

/**
 *  Function TA_CloseSessionEntryPoint
 *  Description:
 *    The Framework calls this function to close a client session.
 *    During the call to this function the implementation can use
 *    any session functions.
 */
__attribute__((visibility ("default"))) void TA_CloseSessionEntryPoint(void *sessionContext)
{
    SLogTrace("---- TA_CloseSessionEntryPoint ----- ");
    (void)sessionContext;  /* -Wunused-parameter */
}
