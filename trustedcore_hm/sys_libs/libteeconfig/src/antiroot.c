/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2018. All rights reserved.
 *
 *
 * Create: 2018-04-23
 *
 * Description: anti root functions for compatible RTOSck SRE syscalls
 */

#include <stdint.h>
#include <hmdrv.h>
#include <hm_msg_type.h> // for ARRAY_SIZE

#include "sre_syscalls_id.h"
#include "root_status_ops.h"

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
__attribute__((visibility("default"))) \
int __SRE_WriteRootStatus(uint32_t status)
{
    uint64_t args[] = {
        status,
    };
    return hm_drv_call(SW_SYSCALL_ROOT_WRITE, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
uint32_t __SRE_ReadRootStatus(void)
{
    return hm_drv_call(SW_SYSCALL_ROOT_READ, NULL, 0);
}

int __is_device_rooted(void)
{
    return hm_drv_call(SW_SYSCALL_IS_DEVICE_ROOTED, NULL, 0);
}
