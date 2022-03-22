/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2018. All rights reserved.
 *
 *
 * Create: 2018-05-06
 *
 * Description: HDCP(High -bandwidth Digital Content Protection) functions f
 *              or compatible RTOSck SRE syscalls
 */

#include <stdint.h>
#include <hmdrv.h>
#include <hm_msg_type.h> // for ARRAY_SIZE

#include "sre_syscalls_id_ext.h"

/*
 * CODEREVIEW CHECKLIST
 * ARG: no need to check, pass to platdrv directly
 * RIGHTS: N/A
 * BUFOVF: N/A
 * LOG: N/A
 * RET:
 *   - return hm_drv_call() return value
 * RACING: N/A
 * LEAK: N/A
 * ARITHOVF: N/A
 */
int32_t __hdcp13_key_all_set(void *key_all)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)key_all, /* Not support 64bit TA now */
    };
    return hm_drv_call(SW_SYSCALL_HDCP13_KEY_ALL_SET, args, ARRAY_SIZE(args));
}

int32_t __hdcp22_key_set(void *duk, void *kpf)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)duk, /* Not support 64bit TA now */
        (uint64_t)(uintptr_t)kpf, /* Not support 64bit TA now */
    };
    return hm_drv_call(SW_SYSCALL_HDCP22_KEY_SET, args, ARRAY_SIZE(args));
}

int32_t __hdcp_dp_enable(unsigned int dp_flag)
{
    uint64_t args[] = {
        (uint64_t)dp_flag,
    };
    return hm_drv_call(SW_SYSCALL_HDCP_DP_ENABLE, args, ARRAY_SIZE(args));
}

int32_t __hdcp_get_value(unsigned int offset)
{
    uint64_t args[] = {
        (uint64_t)offset,
    };
    return hm_drv_call(SW_SYSCALL_HDCP_GET_VALUE, args, ARRAY_SIZE(args));
}

int32_t __hdcp_set_reg(unsigned int reg_value, unsigned int offset)
{
    uint64_t args[] = {
        (uint64_t)reg_value,
        (uint64_t)offset,
    };
    return hm_drv_call(SW_SYSCALL_HDCP_SET_REG, args, ARRAY_SIZE(args));
}

int __hdcp_ioctl(unsigned int cmd_id, unsigned int data,
                 void* buf, unsigned int size)
{
    uint64_t args[] = {
        (uint64_t)cmd_id,
        (uint64_t)data,
        (uint64_t)(uintptr_t)buf, /* Not support 64bit TA now */
        (uint64_t)size,
    };
    return hm_drv_call(SW_SYSCALL_HDCP_IOCTL, args, ARRAY_SIZE(args));
}

int __hdcp_wfd_handle_map(unsigned int *mappedAddr, unsigned int cacheMode,
                          unsigned int secShareFd, unsigned int dataLen)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)mappedAddr,
        (uint64_t)cacheMode,
        (uint64_t)secShareFd,
        (uint64_t)dataLen
    };
    return hm_drv_call(SW_SYSCALL_HDCP_WFD_HANDLE_MAP, args, ARRAY_SIZE(args));
}

int __hdcp_wfd_handle_unmap(unsigned int secShareFd, unsigned int dataLen)
{
    uint64_t args[] = {
        (uint64_t)secShareFd,
        (uint64_t)dataLen
    };
    return hm_drv_call(SW_SYSCALL_HDCP_WFD_HANDLE_UNMAP, args, ARRAY_SIZE(args));
}
