/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: huk service config.
 * Create: 2020-05-22
 */
#include "huk_service_config.h"
#include <securec.h>
#include <tee_inner_uuid.h>
#include <tee_mem_mgmt_api.h>
#include <tee_log.h>
#include "huk_service_msg.h"

static const struct huk_access_table g_huk_access_table[] = {
    { CMD_HUK_DERIVE_TAKEY,         TEE_SERVICE_SSA },
    { CMD_HUK_DERIVE_TAKEY2,        TEE_SERVICE_SSA },
    { CMD_HUK_PROVISION_KEY,        TEE_SERVICE_GLOBAL },
};

bool check_huk_access_permission(const uint32_t cmd_id, const TEE_UUID *uuid)
{
    if (uuid == NULL)
        return false;

    uint32_t i;
    for (i = 0; i < sizeof(g_huk_access_table) / sizeof(g_huk_access_table[0]); i++) {
        if (cmd_id == g_huk_access_table[i].cmd_id &&
            TEE_MemCompare(uuid, &g_huk_access_table[i].uuid, sizeof(*uuid)) == 0)
            return true;
    }
    return false;
}
