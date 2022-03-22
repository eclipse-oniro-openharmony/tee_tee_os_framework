/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: huk service config.
 * Create: 2020-05-22
 */
#include "huk_service_config.h"
#include <securec.h>
#include <tee_inner_uuid.h>
#include <tee_mem_mgmt_api.h>
#include <product_uuid.h>
#include "product_uuid_public.h"
#include <tee_log.h>

bool is_huk_service_compatible_plat(void)
{
#ifdef TEE_HUK_PLAT_COMPATIBLE
    return true;
#else
    return false;
#endif
}

static const TEE_UUID g_huk_ta_access[] = {
    TEE_SERVICE_RPMB,
    TEE_SERVICE_SSA,
    TEE_SERVICE_KEYMASTER,
    TEE_SERVICE_GATEKEEPER,
#ifdef DEF_ENG
    TEE_SERVICE_UT,
#endif
};
static const uint32_t g_huk_ta_access_number = sizeof(g_huk_ta_access) / sizeof(g_huk_ta_access[0]);

/* This permission check is only used on compatible platforms */
TEE_Result check_huk_access_permission(const TEE_UUID *uuid)
{
    uint32_t i;

    if (uuid == NULL) {
        tloge("huk check the TA uuid failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    for (i = 0; i < g_huk_ta_access_number; i++) {
        if (TEE_MemCompare(uuid, &g_huk_ta_access[i], sizeof(*uuid)) == 0)
            return TEE_SUCCESS;
    }

    tlogd("huk check the TA is not supported, uuid is 0x%x\n", uuid->timeLow);
    return TEE_ERROR_GENERIC;
}

bool is_kds_uuid(const TEE_UUID *uuid)
{
    TEE_UUID kds_uuid = TEE_SERVICE_KDS;

    if (uuid == NULL)
        return false;

    if (TEE_MemCompare(uuid, &kds_uuid, sizeof(kds_uuid)) == 0)
        return true;

    return false;
}

static const TEE_UUID g_huk_ta2kds_access[] = {
    TEE_SERVICE_DPHDCP,
#ifdef DEF_ENG
    TEE_SERVICE_UT,
#endif
};
static const uint32_t g_huk_ta2kds_access_number = sizeof(g_huk_ta2kds_access) / sizeof(g_huk_ta2kds_access[0]);
bool is_ta_access_kds_permission(const TEE_UUID *uuid)
{
    uint32_t i;

    if (uuid == NULL)
        return false;

    for (i = 0; i < g_huk_ta2kds_access_number; i++) {
        if (TEE_MemCompare(uuid, &g_huk_ta2kds_access[i], sizeof(*uuid)) == 0)
            return true;
    }
    return false;
}

static TEE_UUID g_provisionkey_uuid[] = {
    TEE_SERVICE_GLOBAL,
    TEE_SERVICE_HDCP,
    TEE_SERVICE_SIGNTOOL,
#ifdef DEF_ENG
    TEE_SERVICE_UT,
#endif
};
static const uint32_t g_provisionkey_uuid_num = sizeof(g_provisionkey_uuid) / sizeof(g_provisionkey_uuid[0]);

bool is_provisionkey_access(const TEE_UUID *uuid)
{
    uint32_t i;

    if (uuid == NULL)
        return false;

    for (i = 0; i < g_provisionkey_uuid_num; i++) {
        if (TEE_MemCompare(uuid, &g_provisionkey_uuid[i], sizeof(*uuid)) == 0)
            return true;
    }

    return false;
}
