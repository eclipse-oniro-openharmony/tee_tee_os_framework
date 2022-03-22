/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: functions to get chip info
 * Create: 2020-4-6
 */
#include "chip_info.h"
#include "chip920_info.h"
#include <stdint.h>
#include <hmdrv.h>
#include <hm_msg_type.h>
#include <sre_syscalls_id.h>
#include "sre_task.h"
#include "tee_defines.h"

__attribute__((visibility("default"))) \
uint32_t get_certkey_info(uint8_t *cert_key, size_t len)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)(cert_key),
        (uint64_t)len,
    };
    return hm_drv_call(SW_SYSCALL_GET_CERT, args, ARRAY_SIZE(args));
}
