/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee npu test
 * Author: SDK
 * Create: 2020-03-02
 * History:
 */

#include "hi_tee_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_module_id.h"
#include "tee_npu_utils.h"
#include "tee_drv_ioctl_npu.h"
#include "tee_npu_test.h"

hi_s32 tee_npu_test_hwts(hi_void)
{
    hi_ulong tmp_data = 0;

    unsigned long args[] = {
        (unsigned long)tmp_data,
    };
    return __tee_npu_ioctl(NPU_TEE_IOCTL_TEST_HWTS, args);
}

