/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Syscall to call MSPC drivers.
 * Create: 2020/06/09
 */

#include <sre_syscalls_id_ext.h>
#include <hmdrv.h>
#include <tee_log.h>
#include <tee_defines.h>

#ifdef CONFIG_HISI_MSPC_IPC_TEST
int32_t __mspc_ipc_test(uint8_t *msg, uint32_t len)
{
    uint64_t args[] = { (uint64_t)(uintptr_t)msg,
                        (uint64_t)len,
                      };

    return hm_drv_call(SW_SYSCALL_MSPC_IPC_TEST, args, ARRAY_SIZE(args));
}

int32_t __mspc_ddr_read(uint32_t addr, uint32_t len, uint8_t *buff, uint32_t *bufflen)
{
    uint64_t args[] = { (uint64_t)addr,
                        (uint64_t)len,
                        (uint64_t)(uintptr_t)buff,
                        (uint64_t)(*bufflen),
                        (uint64_t)(uintptr_t)bufflen,
                        (uint64_t)sizeof(uint32_t),
                      };
    return hm_drv_call(SW_SYSCALL_MSPC_DDR_READ, args, ARRAY_SIZE(args));
}

int32_t __mspc_ddr_write(uint8_t *buff, uint32_t bufflen, uint32_t addr)
{
    uint64_t args[] = { (uint64_t)(uintptr_t)buff,
                        (uint64_t)bufflen,
                        (uint64_t)addr,
                      };
    return hm_drv_call(SW_SYSCALL_MSPC_DDR_WRITE, args, ARRAY_SIZE(args));
}
#endif