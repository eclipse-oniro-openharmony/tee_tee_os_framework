#include <stdint.h>
#include <hm_mman_ext.h>
#include <cache_flush.h>
#include "lib_timer.h"
#include "sre_hwi.h"
#include "sre_task.h"
#include "sre_syscall.h"
#include "sre_syscalls_ext.h"
#include "tee_internal_api.h"
#include "tee_log.h"

#include <sre_syscalls_id.h>
#include <sre_syscalls_id_ext.h>

#include "hmdrv.h"
#define ADDR_OFFSET 32

unsigned int __fr_read_current_time(__attribute__((unused)) void *command_info)
{
    return hm_drv_call(SW_SYSCALL_FR_READ_CURRENT_TIME, NULL, 0);
}

int __fr_secure_memory_map(paddr_t phy_addr, unsigned int size, unsigned int *virt_addr, unsigned int secure_mode,
                           unsigned int cache_mode)
{
    uint64_t args[] = {
        (uint64_t)phy_addr,
        (uint64_t)size,
        (uint64_t)(uintptr_t)virt_addr, /* Not support 64bit TA now */
        (uint64_t)secure_mode,
        (uint64_t)cache_mode,
    };

    int ret = hm_drv_call(SW_SYSCALL_FR_SECURE_TEE_MMAP, args, ARRAY_SIZE(args));
    if (ret == 0) {
        __dma_flush_range(*virt_addr, *virt_addr + size);
    }
    return ret;
}

int __fr_secure_memory_unmap(unsigned int virt_addr, unsigned int size)
{
    uint64_t args[] = {
        (uint64_t)virt_addr,
        (uint64_t)size,
    };
    return hm_drv_call(SW_SYSCALL_FR_SECURE_TEE_UNMAP, args, ARRAY_SIZE(args));
}

int __fr_is_secure_memory(paddr_t addr, unsigned int size, unsigned int protect_id)
{
    uint64_t args[] = {
        (uint64_t)addr,
        (uint64_t)size,
        (uint64_t)protect_id,
    };
    return hm_drv_call(SW_SYSCALL_FR_SECURE_ISSECUREMEM, args, ARRAY_SIZE(args));
}

void __fr_flush_cache(unsigned int start, unsigned int end)
{
    __dma_flush_range(start, end);
}

int __fr_sion_pool_flag_set(unsigned int type)
{
    uint64_t args[] = {
        (uint64_t)type,
    };
    return hm_drv_call(SW_SYSCALL_FR_SECURE_ION_SET, args, ARRAY_SIZE(args));
}

int __fr_sion_pool_flag_unset(unsigned int type)
{
    uint64_t args[] = {
        (uint64_t)type,
    };
    return hm_drv_call(SW_SYSCALL_FR_SECURE_ION_UNSET, args, ARRAY_SIZE(args));
}

int __fr_get_static_phy_addr(paddr_t *addr, unsigned int type, unsigned int index, unsigned int size)
{
    if (addr == NULL) {
        return -1;
    }
    uint32_t ret;
    uint32_t phy_addr = 0;
    uint64_t args[]   = {
        (uint64_t)(uintptr_t)&phy_addr,
        (uint64_t)type,
        (uint64_t)index,
        (uint64_t)size,
    };
    ret   = hm_drv_call(SW_SYSCALL_FR_GET_STATIC_PHY_ADDR, args, ARRAY_SIZE(args));
    *addr = (paddr_t)phy_addr;
    return ret;
}
