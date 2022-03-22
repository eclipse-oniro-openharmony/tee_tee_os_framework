/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Defines the common data type of the system.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#include "sec_mmz.h"
#include "hi_sec_mmz.h"
#include "hi_tee_drv_syscall_id.h"

#ifdef CFG_HI_TEE_SMMU_SUPPORT
#include "hi_smmu.h"
#endif
#include "mmz_ext.h"

#define SECURE_MEM 0

#ifdef CFG_HI_TEE_SEC_MMZ_SUPPORT
unsigned long drv_tee_mmz_new(const char *zone_name, const char *buf_name, int size)
{
    return (unsigned long)new_mmb(buf_name, size, SECURE_MEM, zone_name);
}

unsigned long drv_tee_mmz_delete(unsigned long phys_addr)
{
    delete_mmb((unsigned long)phys_addr);
    return 0;
}

void *drv_tee_mmz_map(unsigned long phys_addr, bool cached)
{
    if (cached) {
        return  remap_mmb_cached((unsigned long)phys_addr);
    }else {
        return remap_mmb((unsigned long)phys_addr);
    }
}

int drv_tee_mmz_unmap(const void *virt_addr)
{
    return unmap_mmb(virt_addr);
}

int drv_tee_mem_flush(void *virt, size_t size)
{
    hi_tee_drv_hal_dcache_flush(virt, size);
    return 0;
}

int drv_tee_mmz_is_sec(unsigned long phys_addr)
{
    return is_sec_mmz(phys_addr);
}

unsigned long drv_tee_mmz_map_to_secsmmu(unsigned long phys_addr, unsigned long size)
{
#ifdef CFG_HI_TEE_SMMU_SUPPORT
    return hisi_sec_map_to_sec_smmu(phys_addr, size, 0);
#else
    return 0;
#endif
}

int drv_tee_mmz_unmap_from_secsmmu(unsigned long sec_smmu)
{
#ifdef CFG_HI_TEE_SMMU_SUPPORT
    return hisi_sec_unmap_from_sec_smmu(sec_smmu, 0);
#else
    return 0;
#endif
}

#endif

