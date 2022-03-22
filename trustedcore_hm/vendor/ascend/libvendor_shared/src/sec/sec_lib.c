/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
* Description: sec libs source file
* Author: chenyao
* Create: 2019/4/2
*/
#include "sre_syscalls_id.h"
#include "hmdrv.h"

#include "syscall_api_common.h"
#include "sec_lib_api.h"

uint32_t __get_provision_key(uint8_t *provision_key)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)(provision_key),
    };

    return hm_drv_call(SW_SYSCALL_SEC_PRO_KEY, args, ARRAY_SIZE(args));
}
