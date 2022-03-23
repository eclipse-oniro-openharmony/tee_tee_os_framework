/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HDCP registers configuration in secure_os
 * Author: Hisilicon
 * Create: 2019-12-29
 */

#include "hdcp_wfd.h"

#include "drv_module.h"
#include "sre_access_control.h"
#include "sre_syscalls_id_ext.h"
#include "drv_param_type.h"
/* keep this last */
#include <hmdrv_stub.h>
/* Map secure handle(fd).
 * Only for wifidisplay(wfd) hdcp secure memory handle map.
 * mappedAddr: the virtual address for wfd hdcp TA to use;
 * secShareFd: secure handle from TA;
 * dataLen: the frame size(mapped buffer len).
*/
int hdcp_wfd_handle_map(unsigned int *mappedAddr, unsigned int cacheMode, unsigned int secShareFd, unsigned int dataLen)
{
    int ret;

    unsigned int bufId = secShareFd;
    struct mem_chunk_list mcl = { 0 };

    mcl.protect_id = 0; // 0: DRM
    mcl.buff_id = bufId;
    mcl.size = dataLen;
    mcl.cache = cacheMode;

    ret = sion_map_user(&mcl);
    if (ret != 0) {
        tloge("[%s]:sion_map_user failed, ret: %d", __func__, ret);
        return ret;
    }
    *mappedAddr = mcl.va;

    return ret;
}

/* Unmap secure handle(fd).
 * Only for wifidisplay(wfd) hdcp secure memory handle unmap.
 * secShareFd: secure handle from TA;
 * dataLen: the frame size(mapped buffer len).
*/
int hdcp_wfd_handle_unmap(unsigned int secShareFd, unsigned int dataLen)
{
    int ret;
    unsigned int bufId = secShareFd;
    struct mem_chunk_list mcl = { 0 };

    mcl.protect_id = 0; // 0: DRM
    mcl.buff_id = bufId;
    mcl.size = dataLen;

    ret = sion_unmap_user(&mcl);
    if (ret != 0) {
        tloge("[%s]:sion_unmap_user failed, ret: %d", __func__,  ret);
    }

    return ret;
}

static int hdcp_wfd_syscall(int swi_id, struct drv_param *params, uint64_t ullPermissions)
{
    uint32_t uwRet;

    if ((params == NULL) || params->args == 0)
        return -1;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
        /* hdcp for wfd(wifidisplay) */
        SYSCALL_PERMISSION(SW_SYSCALL_HDCP_WFD_HANDLE_MAP, ullPermissions, HDCP_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(uint32_t));
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(uint32_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(uint32_t));
        uwRet = (int32_t)hdcp_wfd_handle_map((uint32_t *)(uintptr_t)args[0], (uint32_t)args[1], (uint32_t)args[2],
                                             (uint32_t)args[3]);
        args[0] = uwRet;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_HDCP_WFD_HANDLE_UNMAP, ullPermissions, HDCP_GROUP_PERMISSION)
        uwRet = (int32_t)hdcp_wfd_handle_unmap((uint32_t)args[0], (uint32_t)args[1]);
        args[0] = uwRet;
        SYSCALL_END;
#endif
    default:
        return -1;
    }

    return 0;
}

DECLARE_TC_DRV(
    hdcp_wfd_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    hdcp_wfd_syscall,
    NULL,
    NULL
);
