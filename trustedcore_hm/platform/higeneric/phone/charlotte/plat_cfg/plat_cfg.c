/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2020-12-08
 */
#include <autoconf.h>

#include "plat_cfg.h"
#include "plat_cfg_public.h"

#include <soc_acpu_baseaddr_interface.h>
#include <global_ddr_map.h>
#include <plat_features.h>
#include "uart_register.h"

#ifndef __aarch64__
#error "Only aarch64 is supported!"
#endif

struct platform_info g_plat_cfg = {

    /* value is assigned in boot_kernel_on_current_cpu function */
    .phys_region_start    = 0,
    .phys_region_size     = TEEOS_MEM_SIZE,
    .uart_addr = UART_ADDR,
    .uart_type = UART_DISABLE_FLAG | PL011_V500_TYPE,
    .shmem_offset = SHMEM_OFFSET,
    .shmem_size           = SHMEM_SIZE,

    /* refer to vendor/hisi/ap/platform/charlotte_es/global_ddr_map.h */
    .protected_regions =
        { { ATF_RESERVED_BL31_PHYMEM_BASE, ATF_RESERVED_BL31_PHYMEM_BASE + ATF_RESERVED_BL31_PHYMEM_SIZE } },

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

    .plat_features =
#ifdef CONFIG_ARM64_PAN
    PLAT_DEF_ENG | PLAT_ENABLE_PAN,
#else
    PLAT_DEF_ENG,
#endif
    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions */
    .plat_io_regions = {
        /* .start, .end */
        { SOC_ACPU_TIMER1_BASE_ADDR, SOC_ACPU_TIMER1_BASE_ADDR + TIMER1_BASE_SIZE },
        { SOC_ACPU_TIMER7_BASE_ADDR, SOC_ACPU_TIMER7_BASE_ADDR + TIMER7_BASE_SIZE },
        { RTC_BASE_ADDR, RTC_BASE_ADDR + RTC_BASE_ADDR_SIZE },
        { SOC_ACPU_SCTRL_BASE_ADDR, SOC_ACPU_SCTRL_BASE_ADDR + REG_BASE_SCTRL_SIZE },
        { SOC_ACPU_PERI_CRG_BASE_ADDR, SOC_ACPU_PERI_CRG_BASE_ADDR + REG_BASE_PERI_CRG_SIZE },
        { SOC_ACPU_PCTRL_BASE_ADDR, SOC_ACPU_PCTRL_BASE_ADDR + REG_BASE_PCTRL_SIZE },
        { SOC_ACPU_IPC_BASE_ADDR, SOC_ACPU_IPC_BASE_ADDR + SOC_ACPU_IPC_BASE_ADDR_SIZE },
        { 0, 0 } } /* this is terminator */
};
