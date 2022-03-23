/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: api HDMIRX
 * Author: Hisilicon multimedia interface software group
 * Create: 2020/02/05
 */
#include "tee_api_hdmirx.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_module_id.h"

hi_u32 tee_api_hdmirx_ioctl(unsigned int cmd, hi_void *data)
{
    hi_u32 ret;
    unsigned int args[] = {
        (unsigned int)cmd,
        (unsigned int)(uintptr_t)data,
    };

    ret = hm_drv_call(HI_TEE_SYSCALL_HDMIRX, args, ARRAY_SIZE(args));
    if (ret != HI_SUCCESS) {
        hi_log_err("hm_drv_call fail,ret=%x\n", ret);
        hi_log_alert("hm_drv_call fail,ret=%x\n", ret);
    }

    return ret;
}

