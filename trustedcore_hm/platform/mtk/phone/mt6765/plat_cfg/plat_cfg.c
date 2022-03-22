/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-03
 */
#include "plat_cfg.h"
#include <autoconf.h>
#include "plat_cfg_public.h"
#include <plat_features.h>
#include "uart_register.h"

#ifndef __aarch64__
#error "Only aarch64 is supported!"
#endif

struct platform_info g_plat_cfg = {
    /* To config, set TRUSTEDCORE_PHY_TEXT_BASE in common/var.mk
     * value is assigned in boot_kernel_on_current_cpu function */
    .phys_region_start    = 0,
    .phys_region_size     = TEEOS_MEM_SIZE,
    .uart_addr = UART_ADDR,
    .uart_type = UART_DISABLE_FLAG | PL011_GENERAL_TYPE,
    .shmem_offset = SHMEM_OFFSET,
    .shmem_size           = SHMEM_SIZE,
#ifdef MT6761_IRQ_NR
    /* refer to vendor/mediatek/proprietary/trustzone/atf/v1.4/plat/mediatek/mt6761/include/platform_def.h */
    .protected_regions = { { PROTECTED_REGION_START1, PROTECTED_REGION_END1 } },
#else
    /* refer to vendor/mediatek/proprietary/trustzone/atf/v1.4/plat/mediatek/mt6765/include/memory_layout.h */
    .protected_regions = { { PROTECTED_REGION_START2, PROTECTED_REGION_END2 } },
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

#ifdef MT6761_IRQ_NR
    .spi_num_for_notify = MT6761_SPI_NUM,
#else
    .spi_num_for_notify = MT6765_SPI_NUM,
#endif

    .plat_features = PLAT_DEF_ENG,
    .plat_io_regions = {
        /* .start,            .end */
        { TIMER1_BASE,        TIMER1_BASE + TIMER1_BASE_SIZE },
        { DX_BASE_CC,         DX_BASE_CC + DX_BASE_CC_SIZE },
        { DX_CLOCK_BASE,      DX_CLOCK_BASE + DX_CLOCK_BASE_SIZE },
        { SPI0_BASE_ADDR,     SPI0_BASE_ADDR + SPI0_BASE_SIZE },
        { SPI5_BASE_ADDR,     SPI5_BASE_ADDR + SPI5_BASE_SIZE },
        { GPIO_BASE_ADDR,     GPIO_BASE_ADDR + GPIO_BASE_SIAE },
        { IOCFG_RR_BASE_ADDR, IOCFG_RR_BASE_ADDR + IOCFG_RR_BASE_SIAE },
        { FINGERPRINT_XX,     FINGERPRINT_XX + FINGERPRINT_XX_SIZE },
        { 0, 0 } /* this is terminator */
}

};
