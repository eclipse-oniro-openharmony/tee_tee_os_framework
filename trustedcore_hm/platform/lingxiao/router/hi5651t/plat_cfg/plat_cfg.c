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

struct platform_info g_plat_cfg = {
    /*
     * To config, set TRUSTEDCORE_PHY_TEXT_BASE in common/var.mk
     * value is assigned in boot_kernel_on_current_cpu function
     */
    .phys_region_start = TRUSTEDCORE_PHY_TEXT_BASE,
    /* 16 MB */
    .phys_region_size = TEEOS_MEM_SIZE,
    .uart_addr = UART_ADDR,
    .uart_type = UART_DISABLE_FLAG | PL011_GENERAL_TYPE,
    .shmem_offset = SHMEM_OFFSET,
    .shmem_size = SHMEM_SIZE,

    .gic_config = {
        .version = GIC_V2_VERSION,
        .v2 = {
            .dist = { GIC_DIST_PADDR, GIC_DIST_PADDR + PAGE_SIZE },
            .contr = { GIC_CPU_PADDR, GIC_CPU_PADDR + PAGE_SIZE },
        }
    },

    .spi_num_for_notify = ROUTER_SPI_NUM,
    .plat_features =
#ifdef CONFIG_ARM64_PAN
    PLAT_ENABLE_PAN |
#endif
    PLAT_DEF_ENG,
    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions */
    .plat_io_regions = {
        /* .start, .end */
        { TIMER0_BASE,             TIMER0_BASE + TIMER1_BASE_SIZE },
        { SEC_TRNG0_BASE,          SEC_TRNG0_BASE + SEC_TRNG0_SIZE },
        { SEC_KDF0_BASE,           SEC_KDF0_BASE + SEC_KDF0_SIZE },
        { SEC_PKE_BASE,            SEC_PKE_BASE + SEC_PKE_SIZE },
        { SEC_SEC0_BASE,           SEC_SEC0_BASE + SEC_SEC0_SIZE },
        { HI_SEC_REG_CRG_DIO_BASE, HI_SEC_REG_CRG_DIO_BASE + HI_SEC_REG_CRG_DIO_SIZE },
        /* this is terminator */
        { 0, 0 }
    }
};
