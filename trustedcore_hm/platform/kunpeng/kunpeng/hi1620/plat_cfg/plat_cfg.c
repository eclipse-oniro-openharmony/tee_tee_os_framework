/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Author: wangcong  wangcong48@huawei.com
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

    /* value is assigned in boot_kernel_on_current_cpu function */
    .phys_region_start     = 0,
    .phys_region_size      = TEEOS_MEM_SIZE,
    .uart_addr = UART_ADDR,
    .uart_type = UART_DISABLE_FLAG | UART_LPC_TYPE,
    .shmem_offset  = SHMEM_OFFSET,
    .shmem_size            = SHMEM_SIZE,

    .plat_features         = PLAT_DEF_ENG
#ifdef CONFIG_ARM64_PAN
    | PLAT_ENABLE_PAN
#endif
    ,

    .gic_config = {
        .version = GIC_V3_VERSION,
        .v3 = {
            .dist = { GIC_V3_DIST_ADDR, GIC_V3_DIST_ADDR + GIC_DIST_PAGENUM * PAGE_SIZE },
            .redist_num = GIC_REDIST_NUM,
            .redist_stride = GIC_REDIST_MEMSIZE,
            .redist = {
                { GIC_V3_REDIST1_ADDR, GIC_V3_REDIST1_ADDR + GIC_REDIST_PAGENUM * PAGE_SIZE },
                { GIC_V3_REDIST2_ADDR, GIC_V3_REDIST2_ADDR + GIC_REDIST_PAGENUM * PAGE_SIZE },
                { GIC_V3_REDIST3_ADDR, GIC_V3_REDIST3_ADDR + GIC_REDIST_PAGENUM * PAGE_SIZE },
                { GIC_V3_REDIST4_ADDR, GIC_V3_REDIST4_ADDR + GIC_REDIST_PAGENUM * PAGE_SIZE }
            }
        }
    },

    .spi_num_for_notify    = SPI_NUM,

    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions */
    .plat_io_regions = {
        /* .start,     .end */
        { OS_TIMER0_REG, OS_TIMER0_REG + OS_TIMER0_REG_SIZE },
        { TRNG_BASE_ADDR_CHIP0, TRNG_BASE_ADDR_CHIP0 + TRNG_ADDR_SIZE_CHIP0 },
        { OS_TIMER1_REG, OS_TIMER1_REG + OS_TIMER1_REG_SIZE },
        { SUBCTRL_REG, SUBCTRL_REG + SUBCTRL_REG_SIZE },
        { SEC_PBU_REGS_BASE_ADDR,   SEC_PBU_REGS_BASE_ADDR + PBU_BASE_SIZE },
        { PEH_PF_REGS_BASE_ADDR,   PEH_PF_REGS_BASE_ADDR + PEH_BASE_SIZE },
        { HAC_SUBCTRL_REG_ADDR,   HAC_SUBCTRL_REG_ADDR + HAC_SUBSCTRL_BASE_SIZE },
        { SEC_BASE, SEC_BASE + SEC_BASE_SIZE },
        /* this is terminator */
        { 0, 0 }
    }
};
