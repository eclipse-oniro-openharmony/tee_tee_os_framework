/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Se service whitelist.
 * Create: 2019-12-28
 */
#include "sesrv_permission_config.h"
#include <product_uuid.h>
#include "product_uuid_public.h"
#include "tee_defines.h"
#include "tee_mem_mgmt_api.h"
#include "tee_inner_uuid.h"
#include "tee_log.h"

#define MSP_READER_ID              3

enum mspc_vote_id {
    MSPC_SECFLASH_VOTE_ID   = 0,
    MSPC_BIO_VOTE_ID        = 1,
    MSPC_ROT_VOTE_ID        = 2,
    MSPC_ART_VOTE_ID        = 3,
    MSPC_STRONGBOX_VOTE_ID  = 4,
    MSPC_WEAVER_VOTE_ID     = 5,
    MSPC_FILE_ENCRY_VOTE_ID = 6,
#ifdef DEF_ENG
    MSPC_HISI_TEST1_VOTE_ID = 7,
    MSPC_HISI_TEST2_VOTE_ID = 8,
    MSPC_MAX_VOTE_ID        = 9,
#else
    MSPC_MAX_VOTE_ID        = 7,
#endif
};

struct vote_uuid_t {
    TEE_UUID uuid;
    uint32_t vote_id;
};

static const struct vote_uuid_t g_vote_uuid[] = {
    { TEE_SERVICE_SEC_FLASH,         MSPC_SECFLASH_VOTE_ID },
    { TEE_SERVICE_BIO,               MSPC_BIO_VOTE_ID },
    { TEE_SERVICE_ROT,               MSPC_ROT_VOTE_ID },
    { TEE_SERVICE_ART,               MSPC_ART_VOTE_ID },
    { TEE_SERVICE_STRONGBOX,         MSPC_STRONGBOX_VOTE_ID },
    { TEE_WEAVER_TA,            MSPC_WEAVER_VOTE_ID },
    { TEE_SERVICE_FILE_ENCRY,        MSPC_FILE_ENCRY_VOTE_ID },
#ifdef DEF_ENG
    { TEE_COMMON_TEST_TA1,       MSPC_ART_VOTE_ID },
    { TEE_COMMON_TEST_TA2,       MSPC_WEAVER_VOTE_ID },
#endif
};

TEE_Result se_service_check_msp_permission(const TEE_UUID *uuid)
{
    uint32_t i;

    if (uuid == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (i = 0; i < sizeof(g_vote_uuid) / sizeof(g_vote_uuid[0]); i++) {
        if (TEE_MemCompare(uuid, &(g_vote_uuid[i].uuid), sizeof(*uuid)) == 0)
            return TEE_SUCCESS;
    }

    tloge("check ta permission failed\n");

    return TEE_ERROR_ACCESS_DENIED;
}

bool is_msp_enable(void)
{
#ifdef TEE_SUPPORT_MSP
    return true;
#else
    return false;
#endif
}

bool is_sec_flash_enable(void)
{
#ifdef TEE_SUPPORT_SEC_FLASH
    return true;
#else
    return false;
#endif
}

uint32_t get_vote_id(uint32_t reader_id, const TEE_UUID *uuid)
{
    uint32_t i;

    if (reader_id != MSP_READER_ID)
        return 0;

    if (uuid == NULL)
        return MSPC_MAX_VOTE_ID;

    for (i = 0; i < sizeof(g_vote_uuid) / sizeof(g_vote_uuid[0]); i++) {
        if (TEE_MemCompare(&(g_vote_uuid[i].uuid), uuid, sizeof(*uuid)) == 0)
            return g_vote_uuid[i].vote_id;
    }

    return MSPC_MAX_VOTE_ID;
}
