/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: secflash fs oper access check
 * Author: hemuyang1@huawei.com
 * Create: 2021-11-17
 */
#include "tee_secflash_oper_config.h"
#ifdef CONFIG_SECFS_SECFLASH
#include "secflash_config.h"
#include <tee_mem_mgmt_api.h>

TEE_Result secflash_reset_permission_in_tbl(const TEE_UUID *uuid)
{
    uint32_t i;

    if (uuid == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (i = 0; i < g_secflash_permission_number; i++) {
        if ((TEE_MemCompare(uuid, &g_secflash_permission_config[i].uuid, sizeof(*uuid)) == 0) &&
            ((SECFLASH_SPECIFIC_PERMISSION & g_secflash_permission_config[i].permissions) != 0))
            return TEE_SUCCESS;
    }

    return TEE_ERROR_GENERIC;
}

TEE_Result secflash_status_permission_in_tbl(const TEE_UUID *uuid)
{
    uint32_t i;

    if (uuid == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (i = 0; i < g_secflash_permission_number; i++) {
        if ((TEE_MemCompare(uuid, &g_secflash_permission_config[i].uuid, sizeof(*uuid)) == 0) &&
            ((SECFLASH_GENERIC_PERMISSION & g_secflash_permission_config[i].permissions) != 0))
            return TEE_SUCCESS;
    }

    return TEE_ERROR_GENERIC;
}

TEE_Result secflash_get_ta_threshold_in_tbl(const TEE_UUID *uuid, uint32_t *ta_threshold)
{
    uint32_t i;

    if (uuid == NULL || ta_threshold == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (i = 0; i < g_secflash_ta_number; i++) {
        if (TEE_MemCompare(uuid, &(g_ta_secflash_threshold_config[i].uuid), sizeof(*uuid)) == 0) {
            *ta_threshold = g_ta_secflash_threshold_config[i].threshold;
            return TEE_SUCCESS;
        }
    }

    return TEE_ERROR_GENERIC;
}
#else
TEE_Result secflash_reset_permission_in_tbl(const TEE_UUID *uuid)
{
    (void)uuid;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result secflash_status_permission_in_tbl(const TEE_UUID *uuid)
{
    (void)uuid;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result secflash_get_ta_threshold_in_tbl(const TEE_UUID *uuid, uint32_t *ta_threshold)
{
    (void)uuid;
    (void)ta_threshold;
    return TEE_ERROR_NOT_SUPPORTED;
}
#endif
