/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2022-01-04
 */

#include "plat_cfg.h"
#include "plat_cfg_public.h"
#include <plat_features.h>
#include "uart_register.h"

struct platform_info g_plat_cfg = {
    /*
     * To config, set TRUSTEDCORE_PHY_TEXT_BASE in common/var.mk
     * value is assigned in boot_kernel_on_current_cpu function
     */
    .phys_region_start = 0,
    .uart_addr = UART_ADDR,
    .uart_type = UART_ENABLE_FLAG | PL011_TYPE,
    .shmem_offset = SHMEM_OFFSET,
    .shmem_size           = SHMEM_SIZE,
    /* 6 MB */
    .phys_region_size = TEEOS_MEM_SIZE,

    .gic_config = {
        .version = GIC_V2_VERSION,
        .v2 = {
            .dist = { GIC_V2_DIST_BASE, GIC_V2_DIST_BASE + PAGE_SIZE },
            .contr = { GIC_V2_CPU_BASE, GIC_V2_CPU_BASE + PAGE_SIZE },
        }
    },

    .spi_num_for_notify = HI3516_SPI_NUM,

    .plat_features = PLAT_DEF_ENG,

    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions */
    .extend_datas_io = {
        .extend_magic = 0,
        .extend_length = 0,
        .extend_paras = {0},
        .plat_io_regions = {
            /* .start, .end */
            /* the first region should be UART6 */
            { CPU_CTLR_ADDR, CPU_CTLR_ADDR + CPU_CTLR_SIZE },
            { SEC_TRNG0_BASE, SEC_TRNG0_BASE + SEC_TRNG0_SIZE },
            { SEC_CLK_BASE, SEC_CLK_BASE + SEC_CLK_SIZE },
            { SEC_KLAD_BASE, SEC_KLAD_BASE + SEC_KLAD_SIZE },
            { SEC_OTP_BASE, SEC_OTP_BASE + SEC_OTP_SIZE },
            { TIMER1_BASE, TIMER1_BASE + TIMER1_BASE_SIZE },
            /* this is terminator */
            { 0, 0 }
        }
    }
};
