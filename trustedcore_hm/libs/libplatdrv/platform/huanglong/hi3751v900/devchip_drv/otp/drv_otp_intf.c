/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Module init and exit API for OTP drivers.
 * Author: Linux SDK team
 * Create: 2019-06-20
 */

#include "hi_tee_drv_os_hal.h"
#include "drv_otp_define.h"
#include "hi_tee_drv_syscall_id.h"
#include "drv_legacy_def.h"
#include "drv_otp.h"

int otp_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
    hi_s32 ret;
    if (params == NULL || params->args == 0)
        return -1;
    uint64_t  *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(CMD_OTP_PROCESS, permissions, GENERAL_GROUP_PERMISSION)
        ACCESS_CHECK(args[1], _ioc_size(args[0]))
        hi_debug_otp("Hello, DRV OTP. r0(cmd) = 0x%x\n", args[0]);
        ret = otp_ioctl_impl(args[0], (hi_void *)args[1], _ioc_size(args[0]));
        if (ret != HI_SUCCESS) {
            print_err_hex3(args[0], _ioc_size(args[0]), ret);
            args[0] = ret;
        } else {
            args[0] = 0;
        }
        SYSCALL_END
    default:
        return -EINVAL;
    }
    return 0;
}

hi_s32 otp_suspend(hi_void)
{
    hi_s32 ret = HI_SUCCESS;
    return ret;
}

hi_s32 otp_resume(hi_void)
{
    hi_s32 ret = HI_SUCCESS;
    return ret;
}

hi_s32 otp_init(hi_void)
{
    hi_s32 ret;

    ret = drv_otp_init();
    if (ret != HI_SUCCESS) {
        print_err_func(drv_otp_init, ret);
        return ret;
    }
    hi_tee_drv_hal_printf("load secure otp success. build time:[%s, %s]\n", __DATE__,  __TIME__);
    return ret;
}

hi_tee_drv_hal_driver_init(otp, 0, otp_init, otp_syscall, otp_suspend, otp_resume);

