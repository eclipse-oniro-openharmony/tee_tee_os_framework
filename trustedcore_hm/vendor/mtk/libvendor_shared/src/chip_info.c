/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: functions to get chip info
 * Author: wangzhuochen wangzhuochen1@huawei.com
 * Create: 2020-4-6
 */
#include "chip_info.h"
#include <stdint.h>
#include <hm_mman_ext.h>
#include <hmdrv.h>
#include <hm_msg_type.h> /* for ARRAY_SIZE */
#include <sre_syscalls_id.h>
#include <sre_syscalls_id_ext.h>
#include "lib_timer.h"
#include "sre_task.h"
#include "sre_syscall.h"
#include "tee_defines.h"
#include "tee_bit_ops.h"

__attribute__((visibility("default"))) \
int32_t __tee_hal_get_dieid(uint32_t *in_buffer)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)(in_buffer),
    };
    return hm_drv_call(SW_SYSCALL_TEE_HAL_GET_DIEID, args, ARRAY_SIZE(args));
}
