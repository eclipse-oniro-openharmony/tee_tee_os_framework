/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: internal task enable flag for gtask
 * Create: 2019-10-28
 */

#include "tee_task_config.h"

#include <tee_log.h>
#include <securec.h>

bool is_ssa_enable(void)
{
#if (defined TEE_SUPPORT_SSA_64BIT || defined TEE_SUPPORT_SSA_32BIT)
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
