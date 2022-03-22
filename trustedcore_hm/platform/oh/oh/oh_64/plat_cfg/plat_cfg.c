/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2022-01-04
 */
#include "plat_cfg.h"
#include "plat_cfg_public.h"
#include <plat_features.h>
#include "uart_register.h"

#ifndef __aarch64__
#error "Only aarch64 is supported!"
#endif

struct platform_info g_plat_cfg = {

    /*
     * To config, set TRUSTEDCORE_PHY_TEXT_BASE in common/var.mk
     * value is assigned in boot_kernel_on_current_cpu function
     */
    .phys_region_start      = 0,
    .phys_region_size       = TEEOS_MEM_SIZE,
    .uart_addr = UART_ADDR,
    .uart_type = PL011_TYPE | UART_ENABLE_FLAG,
    .shmem_offset         = SHMEM_OFFSET,
    .shmem_size           = SHMEM_SIZE,
    .protected_regions      = {{ BL31_PADDR_START, BL31_PADDR_END }},

    .plat_features =
#ifdef CONFIG_ARM64_PAN
    PLAT_DEF_ENG | PLAT_ENABLE_PAN,
#else
    PLAT_DEF_ENG,
#endif

    .gic_config = {
        .version = GIC_V3_VERSION,
        .v3 = {
            .dist = { GIC_V3_DIST_PADDR, GIC_V3_DIST_PADDR + GIC_DIST_PAGENUM * PAGE_SIZE },
            .redist_num = GIC_REDIST_NUM,
            .redist_stride = GIC_REDIST_MEMSIZE,
            .redist = {
                { GIC_V3_REDIST_PADDR, GIC_V3_REDIST_PADDR + GIC_REDIST_PAGENUM * PAGE_SIZE }
            }
        }
    },

    .spi_num_for_notify     = SPI_NUM,
    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions */
    .plat_io_regions        = {
        { OS_TIMER0_REG,        OS_TIMER0_REG + OS_TIMER0_REG_SIZE },
        { OS_TIMER1_REG,        OS_TIMER1_REG + OS_TIMER1_REG_SIZE },
        { UART_ADDR,            UART_ADDR + UART_ADDR_SIZE },
        { 0, 0 } /* this is terminator */
    }
};