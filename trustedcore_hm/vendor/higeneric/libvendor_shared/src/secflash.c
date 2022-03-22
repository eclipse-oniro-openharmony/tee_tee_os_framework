/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: secure flash module driver.
 * Create: 2019/9/3
 */

#include <stdint.h>
#include "hm_mman_ext.h"
#include "hm_msg_type.h"

#include "sre_syscall.h"
#include "sre_syscalls_id.h"
#include "sre_syscalls_id_ext.h"

#include "hmdrv.h"

#ifdef CONFIG_HISI_SECFLASH

int32_t __secflash_chip_reset(uint32_t type)
{
    uint64_t args[] = { (uint64_t)type };

    return hm_drv_call(SW_SYSCALL_SECFLASH_RESET, args, ARRAY_SIZE(args));
}

int32_t __secflash_power_save(void)
{
    return hm_drv_call(SW_SYSCALL_SECFLASH_POWER_SAVE, NULL, 0);
}

#endif
