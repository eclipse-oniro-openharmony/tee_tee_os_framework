/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: eps drive interface, Analysis of test commands.
 *              call different test interfaces
 * Create: 2018-12-01
 */

#include "hmdrv.h"
#include "mem_page_ops.h"
#include <sre_syscalls_id_ext.h>

uint32_t __tee_call_hieps_drivers(uint32_t cmd, const char *input, uint32_t max_input_len, const char *parm_info,
                                  uint32_t parm_size)
{
    uint64_t args[] = {
        (uint64_t)cmd,
        (uint64_t)(uintptr_t)input,
        (uint64_t)max_input_len,
        (uint64_t)(uintptr_t)parm_info,
        (uint64_t)parm_size,
    };

#ifdef CONFIG_FEATURE_SEPLAT
    return hm_drv_multithread_call(SW_EPS_CDRM, args, ARRAY_SIZE(args));
#else
    return hm_drv_call(SW_EPS_CDRM, args, ARRAY_SIZE(args));
#endif
}
