/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Defines the common data type of the system.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#include "init.h"
#include "hi_tee_drv_os_hal.h"
#include "tee_drv_mem_layout.h"

#ifdef CFG_HI_TEE_SEC_MMZ_SUPPORT
#include <sec_mmz.h>
#endif

#ifdef CFG_HI_TEE_SMMU_SUPPORT
#include <hi_smmu.h>
#endif

#include "hi_tee_drv_mem.h"

#ifdef TEE_DRV_MEM_INIT_DEBUG
#define MEM_INFO(fmt...)          hi_tee_drv_hal_printf(fmt)
#else
#define MEM_INFO(fmt...)
#endif

static int drv_mem_module_init(void)
{
#if defined(CFG_HI_TEE_SEC_MMZ_SUPPORT)
    void  *zone = NULL;
    unsigned long long zone_size = 0;
    unsigned long long zone_start;

    /* init mmz */
    zone_start = hi_tee_drv_mem_get_zone_range(SEC_MMZ_MEM, &zone_size);
    zone = new_zone("SEC-MMZ", zone_start, zone_size, SECURE_MEM);
    if (zone == NULL) {
        return -1;
    }
    MEM_INFO("Create SEC-MMZ(0x%llx, 0x%llx) success!\n", zone_start, zone_size);

    /* init mmz */
    zone_start = hi_tee_drv_mem_get_zone_range(SEC_SMMU_MMZ, &zone_size);
    zone = new_zone("SMMU-MMZ", zone_start, zone_size, SECURE_MEM);
    if (zone == NULL) {
        return -1;
    }
    MEM_INFO("Create SMMU-MMZ(0x%llx, 0x%llx) success!\n", zone_start, zone_size);
#endif
    return 0;
}

hi_tee_drv_hal_service_init_late(drv_mem, 0, drv_mem_module_init, NULL, NULL, NULL);

