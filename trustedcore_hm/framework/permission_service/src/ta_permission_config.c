/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: permission check functions
 * Create: 2019-12-23
 */
#include "ta_permission_config.h"
#include "tee_mem_mgmt_api.h"

uint32_t get_rpmb_threshold(const TEE_UUID *uuid)
{
    (void)uuid;
    return 0;
}

uint64_t get_rpmb_permission(const TEE_UUID *uuid)
{
    (void)uuid;
    return 0;
}

static bool ta_perm_check(const TEE_UUID *uuid_array, uint32_t array_size, const TEE_UUID *uuid)
{
    uint32_t i;

    if (uuid_array == NULL || uuid == NULL)
        return false;

    for (i = 0; i < array_size; i++) {
        if (TEE_MemCompare(uuid, &(uuid_array[i]), sizeof(*uuid)) == 0)
            return true;
    }

    return false;
}

bool check_sem_permission(const TEE_UUID *uuid)
{
    return ta_perm_check(g_sem_reserved_permsrv,
                         sizeof(g_sem_reserved_permsrv) / sizeof(g_sem_reserved_permsrv[0]), uuid);
}
