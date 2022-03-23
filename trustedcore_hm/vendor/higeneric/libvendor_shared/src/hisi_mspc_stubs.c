/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Syscall to call MSPC drivers stubs.
 * Author : z00452790
 * Create: 2020/07/09
 */

#include "hisi_mspc.h"
#include "stdint.h"

int32_t __hisi_mspc_fac_mode_enter(void)
{
    return -1;
}
int32_t __hisi_mspc_fac_mode_exit(void)
{
    return -1;
}
int32_t __hisi_mspc_power_on(uint32_t vote_id)
{
    (void)vote_id;
    return -1;
}
int32_t __hisi_mspc_power_off(uint32_t vote_id)
{
    (void)vote_id;
    return -1;
}
int32_t __hisi_mspc_recovery(uint32_t flags)
{
    (void)flags;
    return -1;
}
int32_t __hisi_mspc_check_secflash(uint32_t *status)
{
    (void)status;
    return -1;
}
int32_t __hisi_mspc_secflash_writelock(uint32_t is_set_op)
{
    (void)is_set_op;
    return -1;
}
