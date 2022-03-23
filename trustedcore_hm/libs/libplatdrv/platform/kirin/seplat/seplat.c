/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Seplat module driver.
 * Create: 2021/01/03
 */

#include "seplat_errno.h"
#include "seplat_power.h"
#include "seplat_status.h"
#ifdef CONFIG_SEPLAT_TEST
#include "seplat_test.h"
#endif /* CONFIG_SEPLAT_TEST */
#include <drv_module.h>
#include <drv_pal.h>
#include <drv_param_type.h>
#include <sre_access_control.h>
#include <sre_syscalls_id_ext.h>
#include <hmdrv_stub.h>
#include <types.h>

#define SEPLAT_THIS_MODULE              SEPLAT_MODULE_TEEOS

enum {
    ARGS_INDEX0     = 0,
    ARGS_INDEX1     = 1,
    ARGS_INDEX2     = 2,
    ARGS_INDEX3     = 3,
};

static int32_t seplat_init(void)
{
#ifdef CONFIG_SEPLAT_TEST
    if (seplat_test_callback_init() != SEPLAT_OK) {
        SEPLAT_PRINT("seplat init msp channel failed!\n");
        return OS_ERROR;
    }
#endif /* CONFIG_SEPLAT_TEST */

    return SRE_OK;
}

int32_t seplat_syscall(int32_t swi_id, struct drv_param *params,
                       uint64_t permissions)
{
    uint32_t uw_ret;

    if (!params || !params->args) {
        SEPLAT_PRINT("%s: Invalid input!\n", __func__);
        return OS_ERROR;
    }

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_SEPLAT_GET_DTS_STATUS,
                           permissions, SEPLAT_GROUP_PERMISSION)
        uw_ret = seplat_get_dts_status();
        args[ARGS_INDEX0] = uw_ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SEPLAT_POWER_CTRL,
                           permissions, MSPC_GROUP_PERMISSION)

        uw_ret = seplat_power_process((uint32_t)args[ARGS_INDEX0],
                                      (uint32_t)args[ARGS_INDEX1],
                                      (uint32_t)args[ARGS_INDEX2]);
        args[ARGS_INDEX0] = uw_ret;
        SYSCALL_END

        default:
            return OS_ERROR;
    }

    return SRE_OK;
}

DECLARE_TC_DRV(
    seplat_driver,      /* name */
    0,                  /* reserved1 */
    0,                  /* reserved2 */
    0,                  /* reserved3 */
    TC_DRV_MODULE_INIT, /* priority */
    seplat_init,        /* init */
    NULL,               /* handle */
    seplat_syscall,     /* syscall */
    NULL,               /* suspend */
    NULL                /* resume */
);
