/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: This file contains the function required for TEE
 * Author: huzhonghua h00440650
 * Create: 2020-10-30
 */

#include "tee_log.h"
#include "tee_ext_api.h"
#include "tee_mem_mgmt_api.h"

#include "hwsdp_ta.h"
#include "hwsdp_ta_utils.h"

typedef struct {
    const char *pkg_name;
    const uint32_t uid;
} ca_trust_exec;

typedef struct {
    const char *pkg_name;
    const char *modulus;
    const char *pub_exponent;
} ca_trust_apk;

static void add_ca_exec_caller(void)
{
    int32_t i;
    int32_t n;
    TEE_Result ret;
    /* below to add trust caller */
    ca_trust_exec trust_caller[] = {
        {"/dev/hwsdp_ca", 0u},
    };

    n = sizeof(trust_caller) / sizeof(ca_trust_exec);
    for (i = 0; (i < n) && (trust_caller[i].pkg_name != NULL); i++) {
        ret = AddCaller_CA_exec(trust_caller[i].pkg_name, trust_caller[i].uid);
        SLogTrace("add_ca_exec_caller: exec[%s], ret %d", trust_caller[i].pkg_name, ret);
    }
    return;
}

static void add_ca_apk_caller(void)
{
    int32_t i;
    int32_t n;
    TEE_Result ret;
    /* below to add trust caller */
    ca_trust_apk trust_caller[] = {
        {NULL, NULL, NULL}
    };

    n = sizeof(trust_caller) / sizeof(ca_trust_apk);
    for (i = 0; (i < n) && (trust_caller[i].pkg_name != NULL); i++) {
        ret = AddCaller_CA_apk(trust_caller[i].pkg_name, trust_caller[i].modulus, trust_caller[i].pub_exponent);
        SLogTrace("add_ca_apk_caller: apk[%s], ret %d", trust_caller[i].pkg_name, ret);
    }
    return;
}

__attribute__((visibility ("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    SLogTrace("HWSDP_TA: TA_CreateEntryPoint");

    add_ca_exec_caller();
    add_ca_apk_caller();
    return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
__attribute__((visibility ("default"))) void TA_DestroyEntryPoint(void)
{
    hwsdp_destroy_all_modules();
    SLogTrace("HWSDP_TA: TA_DestroyEntryPoint");
    return;
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
__attribute__((visibility ("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param *params, void **sessCtx)
{
    PARAM_NOT_USED(paramTypes);
    PARAM_NOT_USED(params);
    PARAM_NOT_USED(sessCtx);
    SLogTrace("HWSDP_TA: TA_OpenSessionEntryPoint");

    return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
__attribute__((visibility ("default"))) void TA_CloseSessionEntryPoint(void *sessCtx)
{
    PARAM_NOT_USED(sessCtx);
    SLogTrace("HWSDP_TA: TA_CloseSessionEntryPoitnt");
    return;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the parameters
 * come from normal world.
 */
__attribute__((visibility ("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *sessCtx, uint32_t cmdId, uint32_t paramTypes, TEE_Param *params)
{
    TEE_Result teeRes = TEE_SUCCESS;
    PARAM_NOT_USED(sessCtx);

    SLogTrace("HWSDP_TA: enter TA_InvokeCommandEntryPoint");
    switch (cmdId) {
    case CMD_HWSDP_KEY_MANAGER:
        teeRes = hwsdp_proc_message(cmdId, paramTypes, params);
        break;
    default:
        teeRes = TEE_ERROR_BAD_PARAMETERS;
    }
    SLogTrace("HWSDP_TA: TA_InvokeCommandEntryPoint finish, cmd %u, teeRes 0x%x", cmdId, teeRes);

    return teeRes;
}
