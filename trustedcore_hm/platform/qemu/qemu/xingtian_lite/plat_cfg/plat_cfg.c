/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: plat_cfg defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-10
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

    .plat_features          = PLAT_DEF_ENG
#ifdef CONFIG_ARM64_PAN
    | PLAT_ENABLE_PAN
#endif
    ,
    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions */
    .extend_datas_io = {
        .extend_magic = 0,
        .extend_length = 0,
        .extend_paras = {0},
        .plat_io_regions        = {
            { 0, 0 } /* this is terminator */
        }
    }
};
