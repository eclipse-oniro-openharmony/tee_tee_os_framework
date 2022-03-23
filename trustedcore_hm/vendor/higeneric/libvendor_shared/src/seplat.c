/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Drivers for seplat.
 * Create: 2021/01/03
 */

#include <sre_syscalls_id_ext.h>
#include <hmdrv.h>
#include <tee_log.h>
#include <tee_defines.h>

uint32_t seplat_get_dts_status(void)
{
    uint64_t args[] = {};
    return hm_drv_call(SW_SYSCALL_SEPLAT_GET_DTS_STATUS, args, ARRAY_SIZE(args));
}

uint32_t seplat_power_ctrl(uint32_t vote_id, uint32_t cmd, uint32_t op_type)
{
    uint64_t args[] = {
        (uint64_t)vote_id,
        (uint64_t)cmd,
        (uint64_t)op_type,
    };
    return hm_drv_call(SW_SYSCALL_SEPLAT_POWER_CTRL, args, ARRAY_SIZE(args));
}
