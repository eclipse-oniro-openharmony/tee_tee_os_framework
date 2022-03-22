/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: attest ta implemation code
 * Create: 2019-03-25
 * History: 2019-12-10 limingjuan@huawei.com modify csec issue
 */

#include "attestation_ta.h"
#include <securec.h>
#include "tee_log.h"
#include <product_uuid.h>
#include "product_uuid_public.h"
#include <tee_inner_uuid.h>
#include <tee_property_api.h>
#include "tee_ext_api.h"
#include "tee_core_api.h"
#include "crypto_wrapper.h"

static TEE_Result get_uuid_info(struct cert_extension_t *extension_info)
{
    TEE_Result ret;
    caller_info caller_info_data = {0};
    caller_info_data.session_type = SESSION_FROM_TA;

    /* get uuid of app ta */
    ret = TEE_EXT_GetCallerInfo(&caller_info_data, sizeof(caller_info_data));
    if (ret != TEE_SUCCESS) {
        tloge("Get caller info failed, ret=0x%x\n", ret);
        return ret;
    }

    errno_t rc = memcpy_s(&(extension_info->uuid), sizeof(extension_info->uuid),
                          &(caller_info_data.caller_identity.caller_uuid),
                          sizeof(caller_info_data.caller_identity.caller_uuid));
    if (rc != EOK) {
        tloge("Copy uuid of app ta is failed: 0x%x\n", rc);
        return TEE_ERROR_SECURITY;
    }
    return TEE_SUCCESS;
}

static TEE_Result get_version_info(struct cert_extension_t *extension_info)
{
    char api_version[API_VERSION_LEN] = {0};
    uint32_t api_version_size = API_VERSION_LEN;
    uint32_t handle = TEE_PROPSET_TEE_IMPLEMENTATION;
    char impl_version[IMPL_VERSION_LEN] = {0};
    uint32_t impl_version_size = IMPL_VERSION_LEN;
    TEE_Result ret;

    /* get api version */
    ret = TEE_GetPropertyAsString(handle, "gpd.tee.apiversion", api_version, (void *)&api_version_size);
    if (ret != TEE_SUCCESS) {
        tloge("Get api version failed, ret=0x%x\n", ret);
        return ret;
    }
    errno_t rc = memcpy_s(extension_info->tee_api_version, sizeof(extension_info->tee_api_version), api_version,
                          api_version_size);
    if (rc != EOK) {
        tloge("Copy api version of app ta is failed: 0x%x\n", rc);
        return TEE_ERROR_SECURITY;
    }

    /* get implementation version */
    ret = TEE_GetPropertyAsString(handle, "gpd.tee.trustedos.implementation.version", impl_version,
                                  (void *)&impl_version_size);
    if (ret != TEE_SUCCESS) {
        tloge("Get impl version failed, ret=0x%x\n", ret);
        return ret;
    }
    rc = memcpy_s(extension_info->tee_impl_version, sizeof(extension_info->tee_impl_version), impl_version,
                  impl_version_size);
    if (rc != EOK) {
        tloge("Copy impl version of app ta is failed: 0x%x\n", rc);
        return TEE_ERROR_SECURITY;
    }
    return TEE_SUCCESS;
}

static TEE_Result get_extension_info(struct cert_extension_t *extension_info)
{
    TEE_Result ret;

    (void)memset_s(extension_info, sizeof(*extension_info), 0, sizeof(*extension_info));

    ret = get_uuid_info(extension_info);
    if (ret != TEE_SUCCESS) {
        tloge("get uuid is failed, ret=0x%x\n", ret);
        return ret;
    }

    ret = get_version_info(extension_info);
    if (ret != TEE_SUCCESS) {
        tloge("get version is failed, ret=0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result get_attestation_cert_with_huks_ta(const uint8_t *pubkey_der, uint32_t pubkey_der_len,
                                                    uint8_t *cert_chain_out, uint32_t *cert_chain_out_len,
                                                    struct cert_extension_t *extension_info)
{
    TEE_UUID target_uuid = TEE_SERVICE_PKI;
    TEE_Param target_params[PARAM_NUM];
    TEE_TASessionHandle ta2ta_session;
    uint32_t ret_origin = 0;
    TEE_Result ret;

    (void)memset_s(&target_params, sizeof(target_params), 0, sizeof(target_params));
    bool condition =
        (pubkey_der == NULL || cert_chain_out == NULL || pubkey_der_len != TA_PUBKEY_DER_LEN ||
         cert_chain_out_len == NULL || *cert_chain_out_len != ATTEST_TA_CHAIN_MAX_LEN || extension_info == NULL);
    if (condition) {
        tloge("Invalid parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    ret = TEE_OpenTASession(&target_uuid, 0xFFFFFFFF, param_types, target_params, &ta2ta_session, &ret_origin);
    if (ret != TEE_SUCCESS) {
        tloge("Open session pki is failed:ret=0x%x, ret_origin=0x%x\n", ret, ret_origin);
        return ret;
    }

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                  TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE);
    /* public key buffer */
    target_params[PARAM_ZERO].memref.buffer = (void *)pubkey_der;
    target_params[PARAM_ZERO].memref.size = pubkey_der_len;

    /* cert chain buffer */
    target_params[PARAM_ONE].memref.buffer = (void *)cert_chain_out;
    target_params[PARAM_ONE].memref.size = *cert_chain_out_len;

    /* extension buffer */
    target_params[PARAM_TWO].memref.buffer = (void *)extension_info;
    target_params[PARAM_TWO].memref.size = sizeof(*extension_info);

    ret = TEE_InvokeTACommand(ta2ta_session, 0, PKI_KM_CMD_ID_ATTEST_TA_KEY, param_types, target_params, &ret_origin);

    /* update really cert_chain_out_len from hulks ta */
    *cert_chain_out_len = (uint32_t)target_params[PARAM_ONE].memref.size;

    TEE_CloseTASession(ta2ta_session);
    return ret;
}

static TEE_Result check_attestation_at_cmd_params(uint32_t param_types, const TEE_Param *params)
{
    if (params == NULL) {
        tloge("Null parameter data\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* check params types */
    bool condition = ((TEE_PARAM_TYPE_GET(param_types, PARAM_ZERO) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
                      (TEE_PARAM_TYPE_GET(param_types, PARAM_ONE) != TEE_PARAM_TYPE_MEMREF_OUTPUT));
    if (condition) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* params check */
    condition = ((params[PARAM_ZERO].memref.buffer == NULL) || params[PARAM_ZERO].memref.size == 0 ||
                 params[PARAM_ZERO].memref.size != sizeof(rsa_pub_key_t));
    if (condition) {
        tloge("Maybe null params[0].memref.buffer, params[0].memref.size is %zu\n", params[PARAM_ZERO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    condition =
        ((params[PARAM_ONE].memref.buffer == NULL) || (params[PARAM_ONE].memref.size != ATTEST_TA_CHAIN_MAX_LEN));
    if (condition) {
        tloge("Maybe null params[1].memref.buffer, params[1].memref.size is %zu\n", params[PARAM_ONE].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result attestation_ta_init(uint32_t param_types, TEE_Param *params)
{
    TEE_Result ret;
    int32_t pubkey_len = TA_PUBKEY_DER_LEN;
    uint8_t pubkey_der[TA_PUBKEY_DER_LEN] = {0};
    struct cert_extension_t extension_info;

    (void)memset_s(&extension_info, sizeof(extension_info), 0, sizeof(extension_info));
    /* check params */
    ret = check_attestation_at_cmd_params(param_types, params);
    if (ret != TEE_SUCCESS) {
        tloge("Check parameters failed, ret=0x%x\n", ret);
        return ret;
    }

    rsa_pub_key_t *rsa_pub_key = params[PARAM_ZERO].memref.buffer;
    uint8_t *cert_chain_out = params[PARAM_ONE].memref.buffer;
    uint32_t cert_chain_out_len = params[PARAM_ONE].memref.size;

    /* get extend field about uuid, api/implementation version */
    ret = get_extension_info(&extension_info);
    if (ret != TEE_SUCCESS) {
        tloge("Get extension info failed, ret=0x%x\n", ret);
        return ret;
    }

    /* translate public key to der format */
    pubkey_len = rsa_export_pub_sp(pubkey_der, (uint32_t)pubkey_len, rsa_pub_key);
    if (pubkey_len <= 0) {
        tloge("Translate public key to der format is error\n");
        return TEE_ERROR_GENERIC;
    }

    /* call huks ta to obtain certificate chain */
    ret = get_attestation_cert_with_huks_ta(pubkey_der, sizeof(pubkey_der), cert_chain_out, &cert_chain_out_len,
                                            &extension_info);
    if (ret != TEE_SUCCESS) {
        tloge("Get cert for pki is failed, ret=0x%x\n", ret);
        return ret;
    }

    /* update really cert chain len from hulks ta */
    params[PARAM_ONE].memref.size = cert_chain_out_len;
    return TEE_SUCCESS;
}

__attribute__((visibility("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;
    ret = AddCaller_TA_all();
    if (ret != TEE_SUCCESS) {
        tloge("Add caller for all ta is failed, ret=0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

__attribute__((visibility("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
    TEE_Param params[PARAM_NUM], void **session_context)
{
    (void)param_types;
    (void)params;
    (void)session_context;

    return TEE_SUCCESS;
}

static TEE_Result check_app_ta_access(uint32_t cmd_id)
{
    TEE_Result ret;
    /* Check the caller */
    caller_info caller_info_data;
    TEE_UUID caller_uuid;
    TEE_UUID otrp_manger_ta = TEE_SERVICE_OTRP_TA_MANAGER;
    int32_t iret;

    ret = TEE_EXT_GetCallerInfo(&caller_info_data, sizeof(caller_info_data));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to get caller info, ret is 0x%x\n", ret);
        return ret;
    }

    if (caller_info_data.session_type != SESSION_FROM_TA) {
        tloge("Not called from a TA\n");
        return TEE_ERROR_ACCESS_DENIED;
    }

    caller_uuid = caller_info_data.caller_identity.caller_uuid;
    iret = TEE_MemCompare(&caller_uuid, &otrp_manger_ta, sizeof(otrp_manger_ta));
    if (iret == 0)
        return TEE_SUCCESS;

    ret = TEE_EXT_CheckInvokePermission(&caller_uuid, cmd_id);
    if (ret == TEE_SUCCESS)
        return TEE_SUCCESS;

    tloge("check permission failed:0x%x, cmd id:%u, uuid's time low:0x%x\n", ret, cmd_id, caller_uuid.timeLow);
    return TEE_ERROR_ACCESS_DENIED;
}

__attribute__((visibility("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t cmd_id,
                                                                             uint32_t param_types,
                                                                             TEE_Param params[PARAM_NUM])
{
    TEE_Result ret;
    (void)session_context;

    /* Check the caller */
    ret = check_app_ta_access(cmd_id);
    if (ret != TEE_SUCCESS) {
        tloge("Check app ta access is failed: ret = 0x%x\n", ret);
        return TEE_ERROR_ACCESS_DENIED;
    }

    switch (cmd_id) {
    case ATTEST_TA_CMD_ID_INIT:
        ret = attestation_ta_init(param_types, params);
        break;
    default:
        tloge("Invalid attestation_ta cmd id is %u\n", cmd_id);
        ret = TEE_ERROR_INVALID_CMD;
        break;
    }
    if (ret != TEE_SUCCESS)
        tloge("Invoke huks ta failed, ret = 0x%x\n", ret);

    return ret;
}

__attribute__((visibility("default"))) void TA_CloseSessionEntryPoint(void *session_context)
{
    (void)session_context;
    tlogd("Attestation TA: Succeed to CloseSession\n");
}

__attribute__((visibility("default"))) void TA_DestroyEntryPoint(void)
{
    tlogd("Attestation TA: Succeed to DestoryEntryPoint\n");
}
