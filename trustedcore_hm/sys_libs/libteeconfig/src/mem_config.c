/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: tee config implementation
 * Create: 2018-05-18
 */
#include <autoconf.h>
#include <tee_config.h>
#include <product_uuid.h>
#include "tee_mem_mgmt_api.h"
#include "product_uuid_public.h"

static const TEE_UUID g_uncommit_whitelist[] = {
#ifndef SSA_SHRINK_MEMORY
    TEE_SERVICE_SSA,
#endif
    TEE_SERVICE_RPMB,
    TEE_SERVICE_KEYMASTER,
    TEE_SERVICE_GATEKEEPER,
#ifdef TEE_SUPPORT_AI
    TEE_SERVICE_AI,
#endif
#ifdef CONFIG_TEE_TEST_SVM
    TEE_SERVICE_UT,
#endif
#ifdef TEE_SUPPORT_ATTESTATION_TA
    TEE_SERVICE_ATTESTATION_TA,
#endif
    TEE_SERVICE_PERM
};

static const TEE_UUID g_vsroot_flush_whitelist[] = {
#ifdef CONFIG_TEE_TEST_SVM
    TEE_SERVICE_UT,
#endif
#ifdef TEE_SUPPORT_AI
    TEE_SERVICE_AI
#endif
};

bool ta_no_uncommit(const TEE_UUID *uuid)
{
    size_t nr = sizeof(g_uncommit_whitelist) / sizeof(TEE_UUID);
    for (size_t i = 0; i < nr; ++i) {
        if (!TEE_MemCompare(g_uncommit_whitelist + i, uuid, sizeof(TEE_UUID)))
            return true;
    }
#ifdef MEMORY_NO_UC
    return true;
#else
    return false;
#endif
}

bool ta_vsroot_flush(const TEE_UUID *uuid)
{
    if (uuid == NULL)
        return false;
    size_t nr = sizeof(g_vsroot_flush_whitelist) / sizeof(TEE_UUID);
    if (nr == 0)
        return false;

    for (size_t i = 0; i < nr; ++i) {
        if (!TEE_MemCompare(g_vsroot_flush_whitelist + i, uuid, sizeof(TEE_UUID)))
            return true;
    }
    return false;
}
