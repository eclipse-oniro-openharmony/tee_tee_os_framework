/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Create: 2019-05-08
 * Description: vdecry driver interface.
 */
#include <stdint.h>
#include <hm_mman_ext.h>
#include <cache_flush.h>
#include "mem_page_ops.h"
#include "lib_timer.h"
#include "sre_hwi.h"
#include "sre_task.h"
#include "sre_syscall.h"
#include "tee_internal_api.h"
#include "tee_log.h"
#include "mem_page_ops.h" // paddr_t

#include <sre_syscalls_id.h>
#include <sre_syscalls_id_ext.h>

#include "hmdrv.h"

typedef struct mem_map_para {
    paddr_t phy_addr;
    unsigned int size;
    unsigned int secure_mode;
    unsigned int cache_mode;
    unsigned int protect_id;
    unsigned int buff_id;
} MEM_Map_Para_S;

typedef struct mem_unmap_para {
    unsigned int vir_addr;
    unsigned int secure_mode;
    unsigned int size;
    unsigned int protect_id;
    unsigned int buff_id;
} MEM_UnMap_Para_S;

int __SECURE_TEE_Mmap(struct mem_map_para *mem_para, unsigned int *virt_addr)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)mem_para, /* Not support 64bit TA now */
        (uint64_t)(uintptr_t)virt_addr /* Not support 64bit TA now */
    };

    return hm_drv_call(SW_SYSCALL_SECURE_TEE_MMAP, args, ARRAY_SIZE(args));
}

int __SECURE_TEE_Unmap(struct mem_unmap_para *mem_para)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)mem_para /* Not support 64bit TA now */
    };

    return hm_drv_call(SW_SYSCALL_SECURE_TEE_UNMAP, args, ARRAY_SIZE(args));
}

void __SECURE_FlushCache(unsigned int start, unsigned int end)
{
    __dma_flush_range(start, end);
}

int __SECURE_ISSecureMemory(paddr_t addr, unsigned int size, unsigned int protect_id)
{
    uint64_t args[] = { (uint64_t)addr, (uint64_t)((addr >> 32) & 0xffffffff), /* addr offset */
                        (uint64_t)size, (uint64_t)protect_id };

    return hm_drv_call(SW_SYSCALL_SECURE_ISSEUCREMEM, args, ARRAY_SIZE(args));
}
