/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2020. All rights reserved.
 * Description: keymaster task main entry file
 * Create: 2014-01-15
 */
#include <product_uuid.h>
#include "product_uuid_public.h"
#include "keymaster_defs.h"
#include "km_defines.h"
#include "km_keynode.h"
#include "tee_mem_mgmt_api.h"
#include "tee_crypto_api.h"
#include "tee_ext_api.h"
#include "securec.h"
#include "tee_log.h"
#include "km_env.h"
#include "km_auth.h"
#include "km_tag_operation.h"
#include "cmd_handle.h"
#include "km_cmd_auth.h"
#include "km_attest.h"
#include "km_common.h"
#include "km_cmd_handle_provision.h"
#include "km_rollback_resistance.h"
#ifdef BORINGSSL_ENABLE
#include "openssl/cipher.h"
#else
#include "openssl/evp.h"
#endif
/* cc driver config in Android.mk */
#ifdef DX_ENABLE
#include "ccmgr_ops_ext.h" /* __CC_DX_power_down */
#endif

#undef DEBUG_ENABLE
static uint32_t g_keymaster_boot = 0;

__attribute__((visibility("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;
    int32_t ret_val;

    ret = add_caller();
    if (ret != TEE_SUCCESS)
        return ret;

    tlogd("keymaster_task:succeed to CreateEntryPoint\n");
    if (g_keymaster_boot == 0) {
        tlogd("init keymaster ROT\n");
        g_keymaster_boot = 1;
        /* generate_rot after each boot */
        ret_val = generate_rot();
        if (ret_val != 0) {
            tloge("generate_rot failed\n");
            return TEE_ERROR_GENERIC;
        }

        init_auth_list();
        reset_key_record();
    }

    ret_val = init_verify_boot_info();
    if (ret_val != 0) {
        tloge("init verify boot info failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (get_verify_boot_lock_state() == LSTATE_UNLOCKED) {
        tlogd("fastboot unlocked\n");
        set_lock_state(STATE_UNLOCKED);
    }

    ret_val = init_km_mutex();
    if (ret_val != 0) {
        destroy_km_mutex();
        tloge("mutexs init failed\n");
        return TEE_ERROR_GENERIC;
    }

    return ret;
}

/* Note: multi ssessions will be queued, there will no concurrency in open sessions. */
static int32_t g_init_flag = 0;
static uint32_t g_passwd_flag = 0;
uint32_t *get_passwd_flag(void)
{
    return &g_passwd_flag;
}

__attribute__((visibility("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
    TEE_Param params[PARAM_COUNT], void **sessionContext)
{
    TEE_Result ret = TEE_SUCCESS;
    struct session_identity *identity = (struct session_identity *)NULL;

    tlogd("g_init_flag = %d\n", g_init_flag);
    if (TEE_PARAM_TYPE_GET(param_types, 0) == TEE_PARAM_TYPE_VALUE_OUTPUT) {
        if (g_init_flag == 0) {
            g_init_flag = 1;
            params[0].value.a = 1;
        } else {
            params[0].value.a = 0;
        }
    }

    if (TEE_PARAM_TYPE_GET(param_types, 1) == TEE_PARAM_TYPE_VALUE_INPUT) {
        g_passwd_flag = params[1].value.a;
        tlogd("set g_passwd_flag is %u\n", g_passwd_flag);
    }

    if (TEE_PARAM_TYPE_GET(param_types, PARAM_THREE) == TEE_PARAM_TYPE_MEMREF_INPUT) {
        /* When call open session cmd is TEEC_LOGIN_IDENTIFY, the identity size is not larger thn 255-1. */
        if ((params[PARAM_THREE].memref.size > KM_MAX_PACKAGE_NAME_LEN - 1) ||
            sizeof(struct session_identity) > (UINT32_MAX - params[PARAM_THREE].memref.size) ||
            (params[PARAM_THREE].memref.buffer == NULL)) {
            tloge("invalid identity params\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }

        identity =
            (struct session_identity *)TEE_Malloc(sizeof(struct session_identity) + params[PARAM_THREE].memref.size, 0);
        if (identity == NULL) {
            tloge("Failed to allocate mem for session_identify\n");
            return TEE_ERROR_GENERIC;
        }

        identity->len = params[PARAM_THREE].memref.size;
        if (memmove_s((void *)(identity->val), identity->len, params[PARAM_THREE].memref.buffer, identity->len) !=
            EOK) {
            tloge("[error]memmove_s failed\n");
            TEE_Free(identity);
            identity = NULL;
            return TEE_ERROR_GENERIC;
        }
    }
    /* set session context */
    if (sessionContext != NULL) {
        *sessionContext = (void *)identity;
    } else {
        TEE_Free(identity);
        identity = NULL;
    }
    tlogd("keymaster:Succeed to OpenSession\n");
    return ret;
}

__attribute__((visibility("default"))) TEE_Result TA_InvokeCommandEntryPoint(const void *session_context,
    uint32_t cmd_id, uint32_t param_types, TEE_Param params[PARAM_COUNT])
{
    TEE_Result ret = ta_cmd_check(session_context, cmd_id);
    if (ret != TEE_SUCCESS)
        return ret;

    int32_t access_ret = ta_access_check(cmd_id);
#ifdef DX_ENABLE
    uint32_t res = __CC_DX_power_on(); /* keymaster call GP api, it is not aware the hardware driver status */
    if (res != 0) {
        tloge("CC DX power on failed\n");
        return res;
    }
#endif
    if (access_ret == ACCESS_CHECK_VERIFY) {
        ret = km_verify_attestationids_with_param(param_types, params);
        goto inv_out;
    }
    if (access_ret == ACCESS_CHECK_DELETE_KEY) {
        ret = km_delete_key(param_types, params);
        goto inv_out;
    }
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
    if (access_ret == ACCESS_CHECK_POLICY_SET) {
        ret = km_key_policy_set(param_types, params);
        goto inv_out;
    }
#endif
    ret = handle_cmd_id(cmd_id, param_types, params);

inv_out:
#ifdef DX_ENABLE
    res = __CC_DX_power_down();
    if (res != 0) {
        tloge("CC DX power down failed\n");
        return res;
    }
#endif
    if (ret != TEE_SUCCESS) {
        tloge("keymaster invoke failed, ret=%x\n", ret);
        return ret;
    }
    return ret;
}

__attribute__((visibility("default"))) void TA_CloseSessionEntryPoint(void *session_context)
{
    tlogd("keymaster_task:Succeed to CloseSession\n");
    if (session_context != NULL) {
        TEE_Free(session_context);
        session_context = NULL;
    }
}

__attribute__((visibility("default"))) void TA_DestroyEntryPoint(void)
{
    tlogd("keymaster_task:Succeed to DestoryEntryPoint\n");
    destroy_km_mutex();
}
