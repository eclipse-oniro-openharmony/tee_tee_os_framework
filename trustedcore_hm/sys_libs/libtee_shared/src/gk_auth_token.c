/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: gatekeeper auth token api implementation code
 * Create: 2021-12-12
 */
#include <securec.h>
#include <tee_defines.h>
#include <tee_log.h>
#ifdef SUPPORT_GATEKEEPER_TA
#include <tee_core_api.h>
#include <product_uuid_public.h>
#include "gatekeeper.h"
#endif
#include "tee_gk_auth_token.h"

#ifdef SUPPORT_GATEKEEPER_TA
#define PARAM_NUM 4

static TEE_Result get_unlock_timestamp(uint32_t uid, uint64_t *timestamp)
{
    TEE_UUID target_uuid = TEE_SERVICE_GATEKEEPER;
    uint32_t param_types = 0;
    TEE_Param params[PARAM_NUM];
    TEE_TASessionHandle ta2ta_session;
    uint32_t ret_origin = 0;
    uint64_t temp_uid = (uint64_t)uid;

    (void)memset_s(params, sizeof(params), 0, sizeof(params));
    TEE_Result ret = TEE_OpenTASession(&target_uuid, 0xFFFFFFFF, param_types, params, &ta2ta_session, &ret_origin);
    if (ret != TEE_SUCCESS) {
        tloge("Open session failed:0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE);
    params[TEE_PARAM_0].memref.buffer = &temp_uid;
    params[TEE_PARAM_0].memref.size = sizeof(temp_uid);

    ret = TEE_InvokeTACommand(ta2ta_session,
                              0,
                              GK_CMD_ID_GET_AUTH_TOKEN,
                              param_types,
                              params,
                              &ret_origin);
    if (ret != TEE_SUCCESS) {
        tloge("get auth token failed, ret = 0x%x, uid=%u\n", ret, uid);
    } else {
        if (params[TEE_PARAM_0].memref.size < sizeof(*timestamp))
            return TEE_ERROR_GENERIC;
        *timestamp = *(uint64_t *)params[TEE_PARAM_0].memref.buffer;
    }

    TEE_CloseTASession(ta2ta_session);
    return ret;
}
#endif

TEE_Result tee_gatekeeper_get_verify_timestamp(uint32_t uid, uint64_t *timestamp)
{
    if (timestamp == NULL) {
        tloge("invalid parameter\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

#ifdef SUPPORT_GATEKEEPER_TA
    return get_unlock_timestamp(uid, timestamp);
#else
    (void)uid;
    return TEE_ERROR_NOT_SUPPORTED;
#endif
}

