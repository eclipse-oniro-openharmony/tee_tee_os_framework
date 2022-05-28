/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: memory operation defined in platdrv pal.c
 * Create: 2019-11-08
 */
#ifndef PLATDRV_DRV_MEM_H
#define PLATDRV_DRV_MEM_H
#include <sre_typedef.h>
#include <stdint.h>
#include <mem_mode.h> /* cache_mode_type */
#include <dynion.h> /* TEE_PAGEINFO */

#define ACCESS_READ  0x0
#define ACCESS_WRITE 0x1

struct drv_mem_mode {
    secure_mode_type secure_mode;
    cache_mode_type cache_mode;
    user_mode_type user_mode;
};

int32_t sre_mmap(paddr_t base_addr, uint32_t size, uintptr_t *vm_addr, secure_mode_type secure_mode,
                 cache_mode_type cache_mode);
int32_t sre_unmap(uintptr_t virt_addr, uint32_t size);

int32_t tee_mmu_check_access_rights(uint32_t flag, uint32_t va, uint32_t size);
int32_t phy_addr_check(paddr_t phy_addr, uint32_t size);
int32_t check_secureos_addr(paddr_t phy_addr, uint32_t size);

#endif /* PLATDRV_DRV_MEM_H */
