/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description : hdmitx api source file.
 * Author : Hisilicon multimedia interface software group
 * Created : 2020-01-08
 */

#include "hi_tee_drv_syscall_id.h"
#include "tee_api_hdmitx.h"

hi_s32 tee_api_hdmitx_ioctl(unsigned int cmd, struct tee_hdmitx_ioctl *data)
{
    hi_u32 ret;

    unsigned int args[] = {
        (unsigned int)cmd,
        (unsigned int)(uintptr_t)data,
    };
    ret = hm_drv_call(HI_TEE_SYSCALL_HDMITX, args, ARRAY_SIZE(args));
    if (ret != HI_SUCCESS) {
        hi_log_alert("hm_drv_call fail,ret=%d\n", ret);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

