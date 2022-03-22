/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2020. All rights reserved.
 * Description: keymaster cmd authorization
 * Create: 2015-01-17
 */
#include "km_cmd_auth.h"
#include <product_uuid.h>
#include "product_uuid_public.h"
#include "keymaster_defs.h"
#include "tee_mem_mgmt_api.h"
#include "tee_crypto_api.h"
#include "tee_ext_api.h"
#include "securec.h"
#include "tee_log.h"
#include "km_defines.h"
#include "km_keynode.h"
#include "cmd_handle.h"
#include "km_attest.h"
#include "km_cmd_handle_provision.h"
#include "km_rollback_resistance.h"
#ifdef BORINGSSL_ENABLE
#include "openssl/cipher.h"
#else
#include "openssl/evp.h"
#endif

static int32_t handle_access_check(uint32_t cmd_id, const caller_info *caller_info_data)
{
    TEE_UUID pki_id = TEE_SERVICE_PKI;
    TEE_UUID self_device_id = TEE_SERVICE_BYOD;
    int32_t ret;
    switch (cmd_id) {
    case KM_CMD_ID_VERIFY_ATTESTATIONIDS:
        ret = TEE_MemCompare(&(caller_info_data->caller_identity.caller_uuid), &pki_id, sizeof(TEE_UUID));
        /* not pki use KM_CMD_ID_VERIFY_ATTESTATIONIDS, go out */
        if (ret != 0) {
            tloge("This TA can not use cmd KM_CMD_ID_VERIFY_ATTESTATIONIDS\n");
            return -1;
        }
        /* pki use KM_CMD_ID_VERIFY_ATTESTATIONIDS */
        return ACCESS_CHECK_VERIFY;
    case KM_CMD_ID_DELETE_KEY:
        ret = TEE_MemCompare(&(caller_info_data->caller_identity.caller_uuid), &self_device_id, sizeof(TEE_UUID));
        /* not BYOD use KM_CMD_ID_DELETE_KEY, go out */
        if (ret != 0) {
            tloge("This TA can not use cmd KM_CMD_ID_DELETE_KEY\n");
            return -1;
        }
        tlogd("TA call this CMD\n");
        /* BYOD use this CMD only */
        return ACCESS_CHECK_DELETE_KEY;
    case KM_CMD_ID_KB_EIMA_POLICY_SET:
        ret = TEE_MemCompare(&(caller_info_data->caller_identity.caller_uuid), &self_device_id, sizeof(TEE_UUID));
        /* BYOD use this CMD only */
        if (ret != 0) {
            tloge("This TA can not use cmd KM_CMD_ID_KB_EIMA_POLICY_SET");
            return -1;
        }
        return ACCESS_CHECK_POLICY_SET;
    default:
        /* other cmd is not allow TA to access */
        tloge("TA not allow access this cmd\n");
        return ACCESS_CHECK_OTHER;
    }
}

/* this command checks TA2TA to keymaster */
int32_t ta_access_check(uint32_t cmd_id)
{
    TEE_Result ret;
    caller_info caller_info_data;

    ret = TEE_EXT_GetCallerInfo(&caller_info_data, sizeof(caller_info));
    if (ret != 0) {
        tloge("TEE_EXT_GetCallerInfo failed, ret %x\n", ret);
        return (int32_t)ret;
    }

    /* only CA  and PKI TA can  access keymaster TA, and CA is checked in opensession. */
    if (caller_info_data.session_type == SESSION_FROM_CA) {
        /* CA, need to goto switch case. */
        tlogd("CA go to switch case\n");
        return ACCESS_CHECK_FROM_CA;
    }
    return handle_access_check(cmd_id, &caller_info_data);
}

static struct cmd_invoke g_cmd_invoke_list[] = {
    {KM_CMD_ID_GENERATE_KEY, km_generate_key},
    {KM_CMD_ID_GET_KEY_CHARACTER, km_get_key_characteristics},
    {KM_CMD_ID_IMPORT_KEY, km_import_key},
    {KM_CMD_ID_EXPORT_KEY, km_export_key},
    {KM_CMD_ID_ATTEST_KEY, km_attest_key},
    {KM_CMD_ID_UPGRADE, km_upgrade},
    {KM_CMD_ID_BEGIN, km_begin},
    {KM_CMD_ID_UPDATE, km_update},
    {KM_CMD_ID_FINISH, km_finish},
    {KM_CMD_ID_STORE_KB, km_store_kb},
    {KM_CMD_ID_VERIFY_KB, km_verify_kb},
    {KM_CMD_ID_DESTROY_IDENTIFIERS, km_destroy_identifiers}
};

static struct cmd_invok_const g_cmd_invoke_const_list[] = {
    {KM_CMD_ID_CONFIGURE, km_configure},
    {KM_CMD_ID_ABORT, km_abort},
    {KM_CMD_ID_DELETE_KEY, km_delete_key}
};
TEE_Result handle_cmd_id(uint32_t cmd_id, uint32_t param_types, TEE_Param params[PARAM_COUNT])
{
    uint32_t i;
    for (i = 0; i < sizeof(g_cmd_invoke_list) / sizeof(struct cmd_invoke); i++) {
        if (g_cmd_invoke_list[i].cmd == cmd_id)
            return g_cmd_invoke_list[i].func(param_types, params);
    }
    for (i = 0; i < sizeof(g_cmd_invoke_const_list) / sizeof(struct cmd_invok_const); i++) {
        if (g_cmd_invoke_const_list[i].cmd == cmd_id)
            return g_cmd_invoke_const_list[i].func_const(param_types, params);
    }
    switch (cmd_id) {
    case KM_CMD_ID_VERIFY_IDENTIFIERS:
    case KM_CMD_ID_STORE_IDENTIFIERS:
        return km_id_identifiers(param_types, params, cmd_id);
    default:
        tloge("Invalid keymaster_task CMD ID\n");
        return TEE_ERROR_INVALID_CMD;
    }
}

static bool is_identity_valid(const struct session_identity *identity)
{
    bool condition_check = (((strlen(identity->val) != strlen(ATCMDSERVER_PKGN)) ||
                             TEE_MemCompare(identity->val, ATCMDSERVER_PKGN, strlen(ATCMDSERVER_PKGN))) &&
                            ((strlen(identity->val) != strlen(ATCMDSERVER_PKGN_2)) ||
                             TEE_MemCompare(identity->val, ATCMDSERVER_PKGN_2, strlen(ATCMDSERVER_PKGN_2))) &&
                            ((strlen(identity->val) != strlen(ATCMDSERVER_PKGN_3)) ||
                             TEE_MemCompare(identity->val, ATCMDSERVER_PKGN_3, strlen(ATCMDSERVER_PKGN_3))));

    return condition_check;
}

TEE_Result ta_cmd_check(const void *session_context, uint32_t cmd_id)
{
    struct session_identity *identity = (struct session_identity *)session_context;
    bool condition_check = (identity != NULL && ((cmd_id == KM_CMD_ID_STORE_KB) || (cmd_id == KM_CMD_ID_VERIFY_KB) ||
                           (cmd_id == KM_CMD_ID_STORE_IDENTIFIERS) || (cmd_id == KM_CMD_ID_VERIFY_IDENTIFIERS)));

    if (condition_check) {
        condition_check = is_identity_valid(identity);
        if (condition_check == true) {
            tloge("permission error: %s try to access key provision cmd\n", identity->val);
            return TEE_ERROR_ACCESS_DENIED;
        }
    }
    int32_t access_ret = ta_access_check(cmd_id);
    condition_check = ((access_ret != ACCESS_CHECK_OTHER) && (access_ret != ACCESS_CHECK_FROM_CA) &&
                       (access_ret != ACCESS_CHECK_VERIFY) && (access_ret != ACCESS_CHECK_DELETE_KEY) &&
                       (access_ret != ACCESS_CHECK_POLICY_SET));
    if (condition_check == true) {
        tloge("Invalid ret: %d", access_ret);
        return TEE_ERROR_ACCESS_DENIED;
    }
    if (access_ret == ACCESS_CHECK_OTHER) {
        tloge("error access defied\n");
        return TEE_ERROR_ACCESS_DENIED;
    }
    return TEE_SUCCESS;
}

TEE_Result add_caller(void)
{
    TEE_Result ret;
    ret = AddCaller_TA_all();
    if (ret != TEE_SUCCESS)
        return ret;
    struct ca_white_name_t white_name_list[] = {
        { KEYSTORE_HIDL_SERVICE_PKGN, KEYSTORE_HIDL_SERVICE_UID },
        { KEYSTORE_HIDL_SERVICE_4_0_PKGN, KEYSTORE_HIDL_SERVICE_UID},
        { KEYSTORE_PKGN, KEYSTORE_UID },
        { VOLD_PKGN, VOLD_UID },
        { VOLISNOTD_PKGN, VOLISNOTD_UID },
        { ATCMDSERVER_PKGN, ATCMDSERVER_UID },
        { ATCMDSERVER_PKGN_2, ATCMDSERVER_UID },
        { ATCMDSERVER_PKGN_3, ATCMDSERVER_UID }
    };
    uint32_t i;
    for (i = 0; i < sizeof(white_name_list) / sizeof(struct ca_white_name_t); i++) {
        ret = AddCaller_CA_exec(white_name_list[i].name, white_name_list[i].uid);
        if (ret != TEE_SUCCESS)
            return ret;
    }

    return ret;
}
