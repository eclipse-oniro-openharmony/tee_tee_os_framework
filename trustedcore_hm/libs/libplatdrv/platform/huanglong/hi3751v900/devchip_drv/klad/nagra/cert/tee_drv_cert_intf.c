/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Module init and exit API for KeySlot drivers.
 * Author: Linux SDK team
 * Create: 2019-08-23
 */

#include "tee_drv_cert_ioctl.h"

#include "tee_drv_cert.h"

static hi_s32 cert_syscall(hi_s32 swi_id, TSK_REGS_S *regs, UINT64 permissions)
{
    hi_s32 ret;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(CMD_CERT_PROCESS, permissions, GENERAL_GROUP_PERMISSION)
        ACCESS_CHECK(regs->r1, _IOC_SIZE(regs->r0))
        hi_dbg_cert("Hello, DRV CERT. r0(cmd) = 0x%x\n", regs->r0);

        ret = cert_ioctl_impl(regs->r0, (hi_void *)regs->r1, _IOC_SIZE(regs->r0));
        if (ret != HI_SUCCESS) {
            print_err_hex3(regs->r0, _IOC_SIZE(regs->r0), ret);
            regs->r0 = ret;
        } else {
            regs->r0 = 0;
        }
        SYSCALL_END
    default:
        return -EINVAL;
    }

    return HI_SUCCESS;
}

static hi_s32 cert_suspend(struct device *dev)
{
    HI_PRINT("cert suspend ok.\n");
    return HI_SUCCESS;
}

static hi_s32 cert_resume(struct device *dev)
{
    HI_PRINT("cert resume ok.\n");
    return HI_SUCCESS;
}

hi_s32 cert_init(hi_void)
{
    hi_s32 ret;

    ret = drv_cert_init();
    if (ret != HI_SUCCESS) {
        goto out;
    }
out:
    return ret;
}

hi_tee_drv_hal_driver_init(cert, 0, cert_init, cert_syscall, cert_suspend, cert_resume);

