/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: tee drv common interface.
 */

#include "stdio.h"
#include "stdarg.h"

#include "hi_type_dev.h"

#include "sre_access_control.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hmdrv_stub.h"

#include "hi_tee_drv_common.h"
#include "tee_drv_common_ioctl.h"
#include "hi_tee_module_id.h"
#include "drv_legacy_def.h"
#include "tee_common_utils.h"
#include "hi_tee_version.h"

hi_s32 hi_drv_common_delay_us(hi_u32 us)
{
    return HI_SUCCESS;
}

hi_s32 hi_drv_common_get_chip_version(tee_chip_type *chip_type, tee_chip_version *chip_version)
{
    return HI_SUCCESS;
}

hi_s32 tee_drv_common_get_version_info(hi_char *version_info, hi_u32 len, hi_u32 total_size)
{
    return HI_SUCCESS;
}

static hi_s32 tee_drv_common_ioctl(const unsigned int cmd, hi_void *args)
{
    hi_s32 ret = HI_FAILURE;

    switch (cmd) {
        case COMMON_TEE_IOCTL_GET_VERSION: {
            common_tee_version_info *version_info = (common_tee_version_info *)args;
            ret = tee_drv_common_get_version_info(version_info->version, sizeof(version_info->version),
                                                  version_info->total_size);
            break;
        }
        default: {
            HI_ERR_COMMON("Unknown ioctl cmd!\n");
            break;
        }
    }

    return ret;
}

hi_s32 tee_common_syscall(hi_s32 swi_id, struct drv_param *params, unsigned long long permissions)
{
    hi_s32 ret;
    hi_void *argp = HI_NULL;
    hi_u32 addr;
    if (params == NULL || params->args == 0)
        return -1;
    uint64_t  *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_COMMON, permissions, GENERAL_GROUP_PERMISSION)
            /*
             * register usage:
             * r0: cmd, r1: args
             * Note: must call ACCESS_CHECK Convert the virtual address of the api to the virtual address of drv.
             */
            HI_DBG_COMMON("common_syscall regs->r0 0x%x, regs->r1 0x%x!\n", args[0], args[1]);
            ACCESS_CHECK(args[1], _IOC_SIZE(args[0]))
            argp = (hi_void *)args[1];
            ret = tee_drv_common_ioctl(args[0], (void *)args[1]);
            if (ret != HI_SUCCESS) {
                HI_ERR_COMMON("call common ioctl fail: 0x%x!\n", ret);
                args[0] = ret;
            } else {
                args[0] = 0;
            }
            SYSCALL_END
        default:
            return -EINVAL;
    }

    return ret;
}

hi_s32 tee_common_mod_init(hi_void)
{
    hi_tee_drv_hal_printf("load secure common success. build time:[%s, %s]\n", __DATE__,  __TIME__);
    return HI_SUCCESS;
}

hi_tee_drv_hal_driver_init(common, 0, tee_common_mod_init, tee_common_syscall, HI_NULL, HI_NULL);

