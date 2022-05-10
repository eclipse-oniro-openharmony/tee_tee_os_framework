/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: internal task enable flag for gtask
 * Create: 2019-10-28
 */

#include "tee_task_config.h"

#include <tee_log.h>
#include <securec.h>

#define TTF_HASH_SIZE   32
static const uint8_t g_ttf_file_sha[TTF_HASH_SIZE] = {
    0x4e, 0x89, 0x89, 0x0b,
    0xf3, 0x2f, 0x20, 0x4f,
    0x6b, 0x0b, 0x5e, 0x77,
    0x83, 0x8e, 0x27, 0x75,
    0x6c, 0x47, 0x10, 0xb2,
    0xa5, 0xb7, 0xa2, 0xd4,
    0x23, 0x0c, 0x07, 0x7b,
    0xbc, 0xd2, 0x0e, 0xee
};

void get_tui_convergence_fonts_hash(uint8_t *buffer, int32_t len)
{
    if (buffer != NULL && len != 0) {
        if (memcpy_s(buffer, len, g_ttf_file_sha, sizeof(g_ttf_file_sha)) != EOK)
            tloge("get tui convergence fonts hash fail");
    }
}

bool is_ssa_enable(void)
{
#if (defined TEE_SUPPORT_SSA_64BIT || defined TEE_SUPPORT_SSA_32BIT)
    return true;
#else
    return false;
#endif
}

bool is_rpmb_enable(void)
{
#if (defined TEE_SUPPORT_RPMB_64BIT || defined TEE_SUPPORT_RPMB_32BIT)
    return true;
#else
    return false;
#endif
}

bool is_tui_enable(void)
{
#if (defined TEE_SUPPORT_TUI_64BIT || defined TEE_SUPPORT_TUI_32BIT)
    return true;
#else
    return false;
#endif
}

bool is_se_service_enable(void)
{
#if (defined TEE_SUPPORT_SE_SERVICE_32BIT || defined TEE_SUPPORT_SE_SERVICE_64BIT)
    return true;
#else
    return false;
#endif
}
bool is_libfuzzer_enable(void)
{
#if (defined TEE_SUPPORT_LIBFUZZER)
    return true;
#else
    return false;
#endif
}
bool is_tcmgr_service_enable(void)
{
#if (defined TEE_SUPPORT_TCMGR_SERVICE_32BIT || defined TEE_SUPPORT_TCMGR_SERVICE_64BIT)
    return true;
#else
    return false;
#endif
}
