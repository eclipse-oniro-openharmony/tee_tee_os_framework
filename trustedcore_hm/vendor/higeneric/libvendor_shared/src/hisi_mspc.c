/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Syscall to call MSPC drivers.
 * Create: 2020/03/20
 */

#include <sre_syscalls_id_ext.h>
#include <hmdrv.h>
#include <tee_log.h>
#include <tee_defines.h>

enum mspc_factory_cmd {
    MSPC_FAC_MODE_ENTER,
    MSPC_FAC_MODE_EXIT,
    MSPC_FAC_RECOVERY,
    MSPC_FAC_WRITE_LOCK,
};

int32_t __hisi_mspc_check_secflash(uint32_t *status)
{
    uint64_t args[] = { (uint64_t)(uintptr_t)status };

    if (!status) {
        tloge("%s: invalid param!\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return hm_drv_call(SW_SYSCALL_MSPC_CHECK_SECFLASH, args, ARRAY_SIZE(args));
}

int32_t __hisi_mspc_fac_mode_enter(void)
{
    uint64_t args[] = { MSPC_FAC_MODE_ENTER, 0 };

    return hm_drv_multithread_call(SW_SYSCALL_MSPC_FACOTRY_CMD, args, ARRAY_SIZE(args));
}

int32_t __hisi_mspc_fac_mode_exit(void)
{
    uint64_t args[] = { MSPC_FAC_MODE_EXIT, 0 };

    return hm_drv_multithread_call(SW_SYSCALL_MSPC_FACOTRY_CMD, args, ARRAY_SIZE(args));
}

int32_t __hisi_mspc_recovery(uint32_t flags)
{
    uint64_t args[] = { MSPC_FAC_RECOVERY, (uint64_t)flags };

    return hm_drv_multithread_call(SW_SYSCALL_MSPC_FACOTRY_CMD, args, ARRAY_SIZE(args));
}

int32_t __hisi_mspc_power_on(uint32_t vote_id)
{
    uint64_t args[] = { (uint64_t)vote_id };

    return hm_drv_call(SW_SYSCALL_MSPC_POWER_ON, args, ARRAY_SIZE(args));
}

int32_t __hisi_mspc_power_off(uint32_t vote_id)
{
    uint64_t args[] = { (uint64_t)vote_id };

    return hm_drv_call(SW_SYSCALL_MSPC_POWER_OFF, args, ARRAY_SIZE(args));
}

int32_t __hisi_mspc_secflash_writelock(uint32_t is_set_op)
{
    uint64_t args[] = { MSPC_FAC_WRITE_LOCK, (uint64_t)is_set_op };

    return hm_drv_multithread_call(SW_SYSCALL_MSPC_FACOTRY_CMD, args, ARRAY_SIZE(args));
}
