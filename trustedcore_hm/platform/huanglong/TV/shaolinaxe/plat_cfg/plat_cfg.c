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
    /* To config, set TRUSTEDCORE_PHY_TEXT_BASE in var.mkvalue is assigned in boot_kernel_on_current_cpu function */
    .phys_region_start = 0,
    /* 48 MB */
    .phys_region_size = TEEOS_MEM_SIZE,
    .uart_addr = UART_ADDR,
    .uart_type = UART_ENABLE_FLAG | PL011_TYPE,
    .shmem_offset = SHMEM_OFFSET,
    .shmem_size = SHMEM_SIZE,

    .gic_config = {
        .version = GIC_V3_VERSION,
        .v3 = {
            .dist = { REG_BASE_GIC_DIS, REG_BASE_GIC_DIS + GIC_DIST_PAGENUM * PAGE_SIZE },
            .redist_num = GIC_REDIST_NUM,
            .redist_stride = GIC_REDIST_MEMSIZE,
            .redist = {
                { REG_BASE_GIC_REDIS, REG_BASE_GIC_REDIS + GIC_REDIST_PAGENUM * PAGE_SIZE }
            }
        }
    },

    .spi_num_for_notify = SPI_NUM_FOR_NOTIFY,
    .plat_features = PLAT_DEF_ENG,
    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions */
    .plat_io_regions = {
        { TIMER1_BASE,                TIMER1_BASE + TIMER1_BASE_SIZE },
        { 0, 0 }
}

};
