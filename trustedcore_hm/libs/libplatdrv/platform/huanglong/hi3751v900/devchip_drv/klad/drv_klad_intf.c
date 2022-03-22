/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Module init and exit API for KeySlot drivers.
 * Author: Linux SDK team
 * Create: 2019-06-20
 */
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_drv_klad.h"
#include "tee_drv_ioctl_klad.h"

#include "drv_klad_sw.h"
#include "drv_rkp.h"
#include "drv_hkl.h"
#include "drv_klad_hw_func.h"
#include "drv_legacy_def.h"
#include "drv_klad_timestamp.h"


static hi_s32 drv_klad_init(hi_void)
{
    hi_s32 ret;

    klad_timestamp_queue_init();

    ret = rkp_mgmt_init();
    if (ret != HI_SUCCESS) {
        goto out1;
    }

    ret = hkl_mgmt_init();
    if (ret != HI_SUCCESS) {
        goto out2;
    }

    ret = klad_mgmt_init();
    if (ret != HI_SUCCESS) {
        goto out3;
    }

    hi_tee_drv_hkl_ins_init();

    return HI_SUCCESS;
out3:
    hkl_mgmt_exit();
out2:
    rkp_mgmt_exit();
out1:
    return ret;
}

hi_s32 klad_ioctl_impl(unsigned int cmd, hi_void *arg, hi_u32 len)
{
    return fmw_klad_ioctl(cmd, arg, len);
}

int klad_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
    hi_s32 ret;
    if (params == NULL || params->args == 0)
        return -1;
    uint64_t  *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(CMD_KLAD_PROCESS, permissions, GENERAL_GROUP_PERMISSION)
        ACCESS_CHECK(args[1], _ioc_size(args[0]))
        hi_dbg_klad("Hello, DRV KLAD. r0(cmd) = 0x%x\n", args[0]);
        ret = klad_ioctl_impl(args[0], (hi_void *)args[1], _ioc_size(args[0]));
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

hi_s32 klad_suspend(hi_void)
{
    hi_s32 ret;

    ret = klad_mgmt_suspend();
    if (ret != HI_SUCCESS) {
        HI_PRINT("klad suspend failed.\n");
    } else {
        HI_PRINT("klad suspend ok.\n");
    }
    return ret;
}

hi_s32 klad_resume(hi_void)
{
    hi_s32 ret;

    ret = klad_mgmt_resume();
    if (ret != HI_SUCCESS) {
        HI_PRINT("klad resume failed.\n");
    } else {
        HI_PRINT("klad resume ok.\n");
    }
    return ret;
}

hi_s32 klad_init(hi_void)
{
    hi_s32 ret = drv_klad_init();
    hi_tee_drv_hal_printf("load secure klad success. build time:[%s, %s]\n", __DATE__,  __TIME__);
    return ret;
}

hi_tee_drv_hal_driver_init(klad, 0, klad_init, klad_syscall, klad_suspend, klad_resume);

