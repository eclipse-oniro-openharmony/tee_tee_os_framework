/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TUI secure display interfaces with secure_os
 * Author: hanzefeng1@huawei.com
 * Create: 2020-09-01
 */

#include <dr_api/dr_api.h>

#include <iomgr_ext.h>
#include <mem_mode.h>
#include <drv_mem.h>
#include <platdrv.h>
#include <tee_log.h>
#include <drv_mem.h>

uint32_t dr_api_map_io(uint64_t paddr, size_t size, uint32_t mapflag, void **vaddr)
{
    uint32_t temp_vaddr;

    if ((paddr == 0) || (size == 0))
        return DRAPI_OK;
    /*
     * MTK Platform ,IO will be mapped after the Platdrv booted
     * Here will return a vaddr same with paddr
     */
    if ((mapflag & MAP_IO) != 0) {
        void *ptr = hm_io_map(paddr, (void*)(uintptr_t)paddr, PROT_READ | PROT_WRITE);
        temp_vaddr = (uint32_t)(uintptr_t)ptr;
        *vaddr = (void *)(uintptr_t)temp_vaddr;
        return DRAPI_OK;
    }

    return E_DRAPI_INVALID_PARAMETER;
}

uint32_t dr_api_unmap_io(uint64_t paddr, const void *vaddr)
{
    if (paddr == 0)
        return DRAPI_OK;

    return (uint32_t)hm_io_unmap(paddr, vaddr);
}

uint32_t dr_api_map_physical_buffer(uint64_t paddr, size_t size, uint32_t mapflag, void **vaddr)
{
    int32_t ret;
    uintptr_t var = 0;
    secure_mode_type secure_mode = secure;
    cache_mode_type cache_mode = cache;

    if ((paddr == 0) || (size == 0) || (vaddr == NULL)) {
        tloge("drApiMapPhysicalBuffer param fail\n");
        return E_DRAPI_INVALID_PARAMETER;
    }

    if ((mapflag & MAP_IO) != 0) {
        tloge("failed to map register %x\n", paddr);
        return E_DRAPI_INVALID_PARAMETER;
    }

    if ((mapflag & MAP_NOT_SECURE) != 0)
        secure_mode = non_secure;
    if ((mapflag & MAP_UNCACHED) != 0)
        cache_mode = non_cache;

    ret = sre_mmap(paddr, size, &var, secure_mode, cache_mode);
    *vaddr = (void *)var;

    return (uint32_t)ret;
}

uint32_t dr_api_unmap_buffer(void *vaddr, uint32_t size)
{
    return (uint32_t)sre_unmap((uintptr_t)vaddr, size);
}

uint32_t dr_api_cache_data_clean_all(unsigned long start, unsigned long end)
{
    v7_dma_flush_range(start, end);
    return 0;
}
