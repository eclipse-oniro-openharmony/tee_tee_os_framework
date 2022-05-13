/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: some func for tui permission
 * Create: 2020-03-10
 */
#include <stdbool.h>
#include <stdint.h>
#include <tee_defines.h>
#include <tee_mem_mgmt_api.h>
#include <tee_reserve.h>
#include "product_uuid_public.h"

#if (defined TEE_SUPPORT_TUI_64BIT || defined TEE_SUPPORT_TUI_32BIT)
/* add for tui extra dump memory */
const TEE_UUID g_tui_whitelist[] = {
    TEE_SERVICE_U_TA_0, TEE_SERVICE_CCB,    TEE_SERVICE_CFCA,   TEE_SERVICE_BAK,     TEE_SERVICE_U_TA_1,
    TEE_SERVICE_U_TA_2, TEE_SERVICE_U_TA_3, TEE_SERVICE_U_TA_5, TEE_SERVICE_U_TA_4,  TEE_SERVICE_U_TA_6,
    TEE_SERVICE_U_TA_7, TEE_SERVICE_U_TA_8, TEE_SERVICE_U_TA_9, TEE_SERVICE_U_TA_10, TEE_SERVICE_U_TA_11,
};
const uint32_t g_tui_whitelist_num = sizeof(g_tui_whitelist) / sizeof(g_tui_whitelist[0]);

bool check_tui_whitelist(const TEE_UUID *uuid)
{
    uint32_t i;
    if (uuid == NULL)
        return false;

    for (i = 0; i < g_tui_whitelist_num; i++) {
        if (!TEE_MemCompare(uuid, &(g_tui_whitelist[i]), sizeof(TEE_UUID)))
            return true;
    }
    return false;
}
#else
bool check_tui_whitelist(const TEE_UUID *uuid)
{
    (void)uuid;
    return false;
}
#endif
