/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee npu utils impl
 * Author: SDK
 * Create: 2020-02-18
 * History:
 */

#include "hi_tee_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_module_id.h"
#include "tee_drv_ioctl_npu.h"
#include "tee_npu_utils.h"

hi_s32 __tee_npu_ioctl(unsigned long cmd, hi_void *pri_args)
{
    unsigned int args[] = {
        (unsigned long)cmd,
        (uintptr_t)pri_args,
    };
    return hm_drv_call(HI_TEE_SYSCALL_NPU, args, ARRAY_SIZE(args));
}

hi_s32 tee_npu_init(hi_void)
{
    hi_ulong tmp_data = 0;

    unsigned long args[] = {
        (unsigned long)tmp_data,
    };
    return __tee_npu_ioctl(NPU_TEE_IOCTL_GLB_INIT, (void *)args);
}

hi_s32 tee_npu_deinit(hi_void)
{
    hi_ulong tmp_data = 0;

    unsigned long args[] = {
        (unsigned long)tmp_data,
    };
    return __tee_npu_ioctl(NPU_TEE_IOCTL_GLB_DEINIT, (void *)args);
}

