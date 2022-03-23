/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: permission check
 * Author: chengfuxing@huawei.com
 * Create: 2021-12-14
 */
#include "invoke.h"
#include "invoke_check.h"
#include "tee_log.h"
#include "kms_pub_def.h"
#include "product_uuid_public.h"
#include "tee_ext_api.h"

static TEE_Result ca_cmd_check(uint32_t cmd_id)
{
    const uint32_t secmgr_ca_white_list[] = {
        KMS_CMD_CREATE_KEY, KMS_CMD_ENCRYPTO, KMS_CMD_ENCRYPTO_BEGIN, KMS_CMD_ENCRYPTO_UPDATE, KMS_CMD_ENCRYPTO_FINISH,
        KMS_CMD_DECRYPTO, KMS_CMD_DECRYPTO_BEGIN, KMS_CMD_DECRYPTO_UPDATE, KMS_CMD_DECRYPTO_FINISH, KMS_CMD_SIGN,
        KMS_CMD_SIGN_BEGIN, KMS_CMD_SIGN_UPDATE, KMS_CMD_SIGN_FINISH, KMS_CMD_VERIFY, KMS_CMD_VERIFY_BEGIN,
        KMS_CMD_VERIFY_UPDATE, KMS_CMD_VERIFY_FINISH, KMS_CMD_IMPORT_KEY, KMS_CMD_UPDATE_KEY, KMS_CMD_UPDATE_KEY_ID,
        KMS_CMD_DELETE_KEY, KMS_CMD_EXPORT_KEY, KMS_CMD_MAC_GENERATE, KMS_CMD_MAC_GENERATE_BEGIN,
        KMS_CMD_MAC_GENERATE_UPDATE, KMS_CMD_MAC_GENERATE_FINISH, KMS_CMD_DIGEST, KMS_CMD_DIGEST_BEGIN,
        KMS_CMD_DIGEST_UPDATE, KMS_CMD_DIGEST_FINISH, KMS_CMD_RANDOM, KMS_CMD_ABORT, KMS_CMD_DERIVE_KEY,
        KMS_CMD_BATCH_KEY_COMMIT, KMS_CMD_GET_META, KMS_CMD_SEC_EXPORT_KEY,
    };

    uint32_t i;
    for (i = 0; i < sizeof(secmgr_ca_white_list) / sizeof(secmgr_ca_white_list[0]); i++) {
        if (secmgr_ca_white_list[i] == cmd_id)
            return TEE_SUCCESS;
    }
    tloge("CA access cmd %u denied\n", cmd_id);
    return TEE_ERROR_ACCESS_DENIED;
}

static TEE_Result ta_cmd_check(uint32_t cmd_id, const caller_info *caller_info_data)
{
    TEE_UUID vkms_id = TEE_SERVICE_AUDI_VKMS;
    /* only vkms ta can access KMS TA */
    if (TEE_MemCompare(&(caller_info_data->caller_identity.caller_uuid), &vkms_id, sizeof(TEE_UUID)) != 0) {
        tloge("Invalid caller\n");
        return TEE_ERROR_ACCESS_DENIED;
    }
    const uint32_t vkms_cmd_white_list[] = {
        KMS_CMD_DECRYPTO, KMS_CMD_DECRYPTO_BEGIN, KMS_CMD_DECRYPTO_UPDATE, KMS_CMD_DECRYPTO_FINISH,
        KMS_CMD_IMPORT_KEY, KMS_CMD_DELETE_KEY, KMS_CMD_MAC_GENERATE, KMS_CMD_MAC_GENERATE_BEGIN,
        KMS_CMD_MAC_GENERATE_UPDATE, KMS_CMD_MAC_GENERATE_FINISH, KMS_CMD_DIGEST, KMS_CMD_DIGEST_BEGIN,
        KMS_CMD_DIGEST_UPDATE, KMS_CMD_DIGEST_FINISH, KMS_CMD_RANDOM, KMS_CMD_ABORT,
        KMS_CMD_DERIVE_KEY, KMS_CMD_BATCH_KEY_COMMIT, KMS_CMD_GET_META,
    };
    uint32_t i;
    for (i = 0; i < sizeof(vkms_cmd_white_list) / sizeof(vkms_cmd_white_list[0]); i++) {
        if (vkms_cmd_white_list[i] == cmd_id)
            return TEE_SUCCESS;
    }
    tloge("TA access cmd %u denied\n", cmd_id);
    return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result permission_check(uint32_t cmd_id)
{
    TEE_Result ret;
    caller_info caller_info_data;
    ret = TEE_EXT_GetCallerInfo(&caller_info_data, sizeof(caller_info));
    if (ret != TEE_SUCCESS) {
        tloge("Get caller info failed, ret 0x%x\n", ret);
        return ret;
    }

    /* only secmgr CA and vkms TA can access kms TA, CA has been identified */
    if (caller_info_data.session_type == SESSION_FROM_CA)
        return ca_cmd_check(cmd_id);
    return ta_cmd_check(cmd_id, &caller_info_data);
}

bool auth_vkms()
{
    caller_info caller_info_data;
    TEE_UUID vkms_id = TEE_SERVICE_AUDI_VKMS;
    TEE_Result ret = TEE_EXT_GetCallerInfo(&caller_info_data, sizeof(caller_info));
    if (ret != TEE_SUCCESS) {
        tloge("Get caller info failed, ret 0x%x\n", ret);
        return false;
    }
    bool check = ((caller_info_data.session_type == SESSION_FROM_TA) &&
        (TEE_MemCompare(&(caller_info_data.caller_identity.caller_uuid), &vkms_id, sizeof(TEE_UUID)) == 0));
    if (check)
        return true;
    else
        return false;
}
