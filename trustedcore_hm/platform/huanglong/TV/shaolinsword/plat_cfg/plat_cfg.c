/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2020-03
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
    .phys_region_start = 0,
    /* 48 MB */
    .phys_region_size = TEEOS_MEM_SIZE,
    .uart_addr = UART_ADDR,
    .uart_type = UART_ENABLE_FLAG | PL011_TYPE,
    .shmem_offset = SHMEM_OFFSET,
    .shmem_size = SHMEM_SIZE,

    .gic_config = {
        .version = GIC_V2_VERSION,
        .v2 = {
            .dist = { GICV2_DIST_PADDR, GICV2_DIST_PADDR + PAGE_SIZE },
            .contr = { GICV2_CONTR_PADDR, GICV2_CONTR_PADDR + PAGE_SIZE },
        }
    },

    .protected_regions = {},
    .spi_num_for_notify = SPI_NUM_FOR_NOTIFY,
    .plat_features =
#ifdef CONFIG_ARM64_PAN
    PLAT_DEF_ENG | PLAT_ENABLE_PAN,
#else
    PLAT_DEF_ENG,
#endif
    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions */
    .plat_io_regions = {
        { TIMER1_BASE, TIMER1_BASE + TIMER1_BASE_SIZE },
        { TIMER7_BASE, TIMER7_BASE + TIMER7_BASE_SIZE },
        { 0, 0 }
}

};
