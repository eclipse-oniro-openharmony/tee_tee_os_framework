/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: added for hm-teeos
 * Author: hanxuanwei
 * Create: 2018-05-21
 */

#include "vdec_mmap.h"
#include <stdio.h>
#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "mem_page_ops.h"
#include "sre_access_control.h"
#include "drv_module.h"
#include <sys/mman.h>
#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI3660)
#include "secmem.h"
#endif
#include "drv_param_type.h"
#include "drv_pal.h"
#include <hmdrv_stub.h> // hack for `HANDLE_SYSCALL`
#include "drv_task_map.h"
#include "boot_sharedmem.h"

#define UNUSED(x) ((x) = (x))

extern s32 hisi_sion_check_mem(paddr_t addr, u32 size, u32 protectId);

extern int drv_map_paddr_to_task(paddr_t phyAddr, unsigned int size,
                                 unsigned int *virtAddr,
                                 unsigned int secureMode,
                                 unsigned int cacheMode);
extern int drv_unmap_from_task(unsigned int virtAddr, unsigned int size);

int SECURE_TEE_Mmap(MEM_Map_Para_S *memPara,  unsigned int *virtAddr)
{
    int  ui32Result = -1;

    if ((memPara == NULL) || (virtAddr == NULL)) {
        tloge("parameter is null\n");
        return ui32Result;
    }

    struct mem_chunk_list mcl = {0};

    if (memPara->secure_mode == non_secure) {
        ui32Result = (int)drv_map_paddr_to_task(memPara->phy_addr, memPara->size, virtAddr,
                                                (secure_mode_type)memPara->secure_mode,
                                                (cache_mode_type)memPara->cache_mode);
    } else {
        mcl.protect_id = 0;
        mcl.buff_id = memPara->buff_id;
        mcl.size = memPara->size;
        mcl.cache = memPara->cache_mode;
        ui32Result = sion_map_user(&mcl);
        *virtAddr = mcl.va;
    }

    return ui32Result;
}

int SECURE_TEE_Unmap(const MEM_UnMap_Para_S *memPara)
{
    int  ui32Result = -1;

    if (memPara == NULL) {
        tloge("parameter is null\n");
        return ui32Result;
    }

    if (memPara->secure_mode == non_secure) {
        ui32Result = drv_unmap_from_task(memPara->vir_addr, memPara->size);
    } else {
        struct mem_chunk_list mcl = {0};
        mcl.protect_id = 0;
        mcl.buff_id = memPara->buff_id;
        mcl.size = memPara->size;
        ui32Result = sion_unmap_user(&mcl);
    }

    return ui32Result;
}

int SECURE_ISSecureMemory(paddr_t addr, unsigned int size, unsigned int protectId)
{
    return (int)hisi_sion_check_mem(addr, size, protectId);
}

int VideoDecryptSyscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
    UINT32 uwRet;

    if (params == NULL || params->args == 0) {
        tloge("params is null\n");
        return -1;
    }

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id)
    {
        SYSCALL_PERMISSION(SW_SYSCALL_SECURE_TEE_MMAP, permissions, VDEC_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(MEM_Map_Para_S)); // 0: mem_para
        ACCESS_READ_RIGHT_CHECK(args[0], sizeof(MEM_Map_Para_S)); // 0: mem_para
        ACCESS_CHECK_A64(args[1], sizeof(UINT32)); // 1: virt_addr
        ACCESS_WRITE_RIGHT_CHECK(args[1], sizeof(UINT32)); // 1: virt_addr
        // 0: mem_para, 1: virt_addr
        uwRet = (UINT32)SECURE_TEE_Mmap((struct mem_map_para *)(uintptr_t)args[0],
            (unsigned int *)(uintptr_t)args[1]);
        args[0] = uwRet; // 0: mem_para
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SECURE_TEE_UNMAP, permissions, VDEC_GROUP_PERMISSION) // 0: mem_para
        ACCESS_CHECK_A64(args[0], sizeof(MEM_UnMap_Para_S)); // 0: mem_para
        uwRet = (UINT32)SECURE_TEE_Unmap((struct mem_unmap_para *)(uintptr_t)args[0]); // 0: mem_para
        args[0] = uwRet; // 0: mem_para
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SECURE_ISSEUCREMEM, permissions, VDEC_GROUP_PERMISSION)
        // 0: addr, 1:offset
        uwRet = (UINT32)SECURE_ISSecureMemory(((paddr_t)(args[1]) << 32) | args[0],
            (unsigned int)args[2], (unsigned int)args[3]); // 2: size, 3: protect_id
        args[0] = uwRet;// 0: addr
        SYSCALL_END

        default:
            return -1;
    }

    return 0;
}

DECLARE_TC_DRV(
        video_decrypt,
        0,
        0,
        0,
        TC_DRV_MODULE_INIT,
        NULL,
        NULL,
        VideoDecryptSyscall,
        NULL,
        NULL
        );
