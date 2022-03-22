/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2018. All rights reserved.
 *
 *
 * Create: 2018-04-07
 *
 * Description: security boot functions for compatible RTOSck SRE syscalls
 */

#include <stdint.h>
#include <hm_mman_ext.h>
#include <hmdrv.h>
#include <hm_msg_type.h> /* for ARRAY_SIZE */

#include "lib_timer.h"
#include "sre_task.h"
#include "sre_syscall.h"
#include "tee_defines.h"

#include <sre_syscalls_id.h>
#include <sre_syscalls_id_ext.h>
#include "tee_bit_ops.h"
#include "secboot_drv_call.h"

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
#define HIGH_SHIFT 32

__attribute__((visibility("default"))) \
UINT32 __hisi_secboot_process_soc_addr(UINT32 soc_type, const paddr_t src_addr, UINT32 process_type)
{
    uint64_t args[] = {
        (uint64_t)soc_type,
        (uint64_t)src_addr,
        (uint64_t)process_type,
    };
    return hm_drv_call(SW_PROCESS_SOC_ADDR, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
UINT32 __hisi_secboot_copy_soc_data(UINT32 soc_type, UINT32 offset, const paddr_t src_addr, unsigned len)
{
    uint64_t args[] = {
        (uint64_t)soc_type,
        (uint64_t)offset,
        (uint64_t)src_addr,
        (uint64_t)len,
    };
    return hm_drv_call(SW_COPY_SOC_DATA_TYPE, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
UINT32 __hisi_secboot_soc_verification(UINT32 socType, UINT32 vrlAddress, paddr_t imageAddress, unsigned int lock_state)
{
    uint64_t args[] = {
        (uint64_t)socType,
        (uint64_t)vrlAddress,
        (uint64_t)imageAddress,
        (uint64_t)lock_state,
    };
    return hm_drv_call(SW_VERIFY_SOC_DATA_TYPE, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
UINT32 __secboot_get_cuid(UINT8 *cuid, UINT32 len)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)cuid,
        (uint64_t)len,
    };
    return hm_drv_call(SW_GET_CUID, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
UINT32 __hisi_secboot_soc_reset(UINT32 soc_type)
{
    uint64_t args[] = {
        (uint64_t)soc_type,
    };
    return hm_drv_call(SW_SOC_IMAGE_RESET, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
UINT32 __hisi_secboot_soc_set(UINT32 soc_type)
{
    uint64_t args[] = {
        (uint64_t)soc_type,
    };
    return hm_drv_call(SW_SOC_IMAGE_SET, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
void __hisi_secboot_get_vrl_addr(UINT32 vrl_address)
{
    uint64_t args[] = {
        (uint64_t)vrl_address,
    };
    (void)hm_drv_call(SW_SOC_GET_VRL_ADDR, args, ARRAY_SIZE(args));
}

__attribute__((visibility("default"))) \
int __bsp_modem_call(unsigned int func_cmd, unsigned int arg1, void *arg2, unsigned int arg3)
{
    uint64_t args[] = {
        (uint64_t)func_cmd,
        (uint64_t)arg1,
        (uint64_t)(uintptr_t)arg2, /* Not support 64bit TA now */
        (uint64_t)arg3,
    };
    return hm_drv_call(SW_SYSCALL_BSP_MODEM_CALL, args, ARRAY_SIZE(args));
}
