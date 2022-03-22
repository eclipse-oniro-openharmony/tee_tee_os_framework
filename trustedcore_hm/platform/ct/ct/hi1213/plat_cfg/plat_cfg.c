/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: plat_cfg defines
 * Author: hemuyang1@huawei.com
 * Create: 2021-03-09
 */

#include "plat_cfg.h"
#include "plat_cfg_public.h"
#include <plat_features.h>
#include "uart_register.h"

#ifndef __aarch64__
#error "Only aarch64 is supported!"
#endif

/* keep layout sync with hm-teeos/kernel/include/arch/arm/arch/elfloader.h */
struct platform_info g_plat_cfg = {
    .phys_region_start = 0,
    .phys_region_size = TEEOS_MEM_SIZE,
    .uart_addr = UART_ADDR,
    .uart_type = UART_DISABLE_FLAG | PL011_TYPE,
    .shmem_offset = SHMEM_OFFSET,
    .shmem_size = SHMEM_SIZE,

    .plat_features =
#ifdef CONFIG_ARM64_PAN
    PLAT_DEF_ENG | PLAT_ENABLE_PAN,
#else
    PLAT_DEF_ENG,
#endif

    .gic_config = {
        .version = GIC_V3_VERSION,
        .v3 = {
            .dist = { GIC_V3_DIST_ADDR, GIC_V3_DIST_ADDR + GIC_DIST_PAGENUM * PAGE_SIZE },
            .redist_num = GIC_REDIST_NUM,
            .redist_stride = GIC_REDIST_MEMSIZE,
            .redist = {
                { GIC_V3_REDIST_ADDR, GIC_V3_REDIST_ADDR + GIC_REDIST_PAGENUM * PAGE_SIZE }
            }
        }
    },

    .spi_num_for_notify = SPI_NUM,

    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions */
    .plat_io_regions = {
        /* the second region should be freerunning timer */
        { OS_TIMER0_REG,        OS_TIMER0_REG + OS_TIMER0_REG_SIZE },
        /* the third region should be trng for random gen */
        { TRNG_BASE_ADDR_CHIP0, TRNG_BASE_ADDR_CHIP0 + TRNG_ADDR_SIZE_CHIP0 },
        { OS_TIMER1_REG,        OS_TIMER1_REG + OS_TIMER1_REG_SIZE },
        { SUBCTRL_REG,          SUBCTRL_REG + SUBCTRL_REG_SIZE },
        /* this is terminator */
        { 0, 0 }
    }
};
