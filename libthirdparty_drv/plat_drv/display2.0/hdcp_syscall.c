/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hdcp driver syscall
 * Author:
 * Create: 2019-12
 */
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_ext.h"
#include "drv_module.h"
#include "sre_syscalls_id.h"
#include "sre_access_control.h"
#include "drv_pal.h"
#include "hisi_hdcp.h"

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#include "hdcp_wfd.h"
#endif
#include "drv_param_type.h"
#include <hmdrv_stub.h> // keep this last

int hdcp_driver_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    if (params == NULL || params->args == 0)
        return -1;

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
    uint32_t ret = 0;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
#else
    (void)permissions;
#endif

    HANDLE_SYSCALL(swi_id) {
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)

        SYSCALL_PERMISSION(SW_SYSCALL_HDCP13_KEY_ALL_SET, permissions,
                           DPHDCP_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(hdcp13_all_key_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(hdcp13_all_key_t));
        ret = hdcp13_key_all_set((hdcp13_all_key_t*)(uintptr_t)args[0]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_HDCP22_KEY_SET, permissions,
                           DPHDCP_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(hdcp22_key_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(hdcp22_key_t));
        ACCESS_CHECK_A64(args[1], sizeof(hdcp22_key_t));
        ACCESS_READ_RIGHT_CHECK(args[1], sizeof(hdcp22_key_t));
        ret = hdcp22_key_set((hdcp22_key_t*)(uintptr_t)args[0], (hdcp22_key_t*)(uintptr_t)args[1]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_HDCP_DP_ENABLE, permissions,
                           DPHDCP_GROUP_PERMISSION)
        ret = hdcp_dp_enable((unsigned int)args[0]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_HDCP_GET_VALUE, permissions,
                           DPHDCP_GROUP_PERMISSION)
        ret = hdcp_get_value((unsigned int)args[0]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_HDCP_SET_REG, permissions,
                           DPHDCP_GROUP_PERMISSION)
        ret = hdcp_set_reg((unsigned int)args[0], (unsigned int)args[1]);
        args[0] = ret;
        SYSCALL_END;

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI3670)
        SYSCALL_PERMISSION(SW_SYSCALL_HDCP_IOCTL, permissions, DPHDCP_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[2], (unsigned int)args[3]);
        ACCESS_READ_RIGHT_CHECK(args[2], (unsigned int)args[3]);
        ACCESS_WRITE_RIGHT_CHECK(args[2], (unsigned int)args[3]);
        ret = hdcp_ioctl((unsigned int)args[0], (unsigned int)args[1],
            (void*)(uintptr_t)args[2], (unsigned int)args[3]);
        args[0] = ret;
        SYSCALL_END;
#endif
#endif

    default:
        return -1;
    }

    return 0;
}

DECLARE_TC_DRV(
    hdcp_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    hdcp_driver_syscall,
    NULL,
    NULL
);
