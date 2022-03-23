/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tee drv tsr2rcipher interface.
 * Author: sdk
 * Create: 2019-08-02
 */

#include "stdio.h"
#include "stdarg.h"

#include "hi_type_dev.h"

#include "sre_access_control.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hmdrv_stub.h"

#include "hi_tee_drv_tsr2rcipher.h"
#include "tee_drv_ioctl_tsr2rcipher.h"
#include "tee_drv_tsr2rcipher_func.h"
#include "hi_tee_module_id.h"

static hi_s32 tee_drv_tsr2rcipher_ioctl(const unsigned int cmd, hi_void *args)
{
    hi_s32 ret = HI_FAILURE;

    TSC_CHECK_NULL_POINTER(args);

    switch (cmd) {
        case TSR2RCIPHER_TEE_IOCTL_GET_CAP: {
            tsr2rcipher_capability *info = (tsr2rcipher_capability *)args;
            ret = hi_drv_tsr2rcipher_get_capability(info);
            break;
        }
        case TSR2RCIPHER_TEE_IOCTL_CREATE: {
            tsr2rcipher_create_info *info = (tsr2rcipher_create_info *)args;
            ret = hi_drv_tsr2rcipher_create(&info->tsc_attr, &info->handle);
            break;
        }
        case TSR2RCIPHER_TEE_IOCTL_DESTROY: {
            hi_handle *handle = (hi_handle *)args;
            ret = hi_drv_tsr2rcipher_destroy(*handle);
            break;
        }
        case TSR2RCIPHER_TEE_IOCTL_GET_ATTR: {
            tsr2rcipher_attr_info *info = (tsr2rcipher_attr_info *)args;
            ret = hi_drv_tsr2rcipher_get_attr(info->handle, &info->tsc_attr);
            break;
        }
        case TSR2RCIPHER_TEE_IOCTL_SET_ATTR: {
            tsr2rcipher_attr_info *info = (tsr2rcipher_attr_info *)args;
            ret = hi_drv_tsr2rcipher_set_attr(info->handle, &info->tsc_attr);
            break;
        }
        case TSR2RCIPHER_TEE_IOCTL_GET_KS: {
            tsr2rcipher_get_ks_handle *info = (tsr2rcipher_get_ks_handle *)args;
            ret = hi_drv_tsr2rcipher_get_keyslot_handle(info->tsc_handle, &info->ks_handle);
            break;
        }
        case TSR2RCIPHER_TEE_IOCTL_ATTACH_KS: {
            tsr2rcipher_associate_ks *info = (tsr2rcipher_associate_ks *)args;
            ret = hi_drv_tsr2rcipher_attach_keyslot(info->tsc_handle, info->ks_handle);
            break;
        }
        case TSR2RCIPHER_TEE_IOCTL_DETACH_KS: {
            tsr2rcipher_associate_ks *info = (tsr2rcipher_associate_ks *)args;
            ret = hi_drv_tsr2rcipher_detach_keyslot(info->tsc_handle, info->ks_handle);
            break;
        }
        case TSR2RCIPHER_TEE_IOCTL_SET_IV: {
            tsr2rcipher_set_iv_info *info = (tsr2rcipher_set_iv_info *)args;
            ret = hi_drv_tsr2rcipher_set_iv(info->handle, info->type, info->iv, info->len);
            break;
        }
        case TSR2RCIPHER_TEE_IOCTL_ENCRYPT: {
            tsr2rcipher_deal_data_info *info = (tsr2rcipher_deal_data_info *)args;
            ret = hi_drv_tsr2rcipher_encrypt(info->handle, info->src_buf, info->dst_buf, info->data_len);
            break;
        }
        case TSR2RCIPHER_TEE_IOCTL_DECRYPT: {
            tsr2rcipher_deal_data_info *info = (tsr2rcipher_deal_data_info *)args;
            ret = hi_drv_tsr2rcipher_decrypt(info->handle, info->src_buf, info->dst_buf, info->data_len);
            break;
        }
        default: {
            hi_log_err("Unknown ioctl cmd!\n");
            break;
        }
    }

    return ret;
}

hi_s32 tee_tsr2rcipher_syscall(hi_s32 swi_id, TSK_REGS_S *regs, unsigned long long permissions)
{
    hi_s32 ret;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_TSR2RCIPHER, permissions, GENERAL_GROUP_PERMISSION)
            /*
             * register usage:
             * r0: cmd, r1: args
             * Note: must call ACCESS_CHECK Convert the virtual address of the api to the virtual address of drv.
             */
            hi_log_dbg("tsr2rcipher_syscall regs->r0 0x%x, regs->r1 0x%x!\n", regs->r0, regs->r1);
            ACCESS_CHECK(regs->r1, _ioc_size(regs->r0))
            ret = tee_drv_tsr2rcipher_ioctl(regs->r0, (void *)regs->r1);
            if (ret != HI_SUCCESS) {
                hi_log_err("call tsr2rcipher ioctl[cmd: 0x%x] fail: 0x%x!\n", regs->r0, ret);
                regs->r0 = ret;
            } else {
                regs->r0 = 0;
            }
            SYSCALL_END
        default:
            return -EINVAL;
    }

    return 0;
}

hi_s32 tee_tsr2rcipher_suspend(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 tee_tsr2rcipher_resume(hi_void)
{
    return HI_SUCCESS;
}

hi_s32 tee_tsr2rcipher_mod_init(hi_void)
{
    hi_s32 ret;

    ret = tsr2rcipher_mod_init_impl();
    if (ret != HI_SUCCESS) {
        return HI_FAILURE;
    }

    hi_tee_drv_hal_printf("load secure tsr2rcipher success. build time:[%s, %s]\n", __DATE__,  __TIME__);
    return HI_SUCCESS;
}

hi_tee_drv_hal_driver_init_late(tsr2rcipher, 0, tee_tsr2rcipher_mod_init, tee_tsr2rcipher_syscall,
    tee_tsr2rcipher_suspend, tee_tsr2rcipher_resume);

