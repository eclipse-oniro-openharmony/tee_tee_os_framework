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
    .phys_region_size     = 0,
    .uart_addr = UART_ADDR,
    .uart_type = UART_DISABLE_FLAG | PL011_GENERAL_TYPE,
    .shmem_offset = SHMEM_OFFSET,
    .shmem_size           = SHMEM_SIZE,
    .protected_regions    = { { PROTECTED_REGION_START1, PROTECTED_REGION_END1 } },

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

    .spi_num_for_notify    = MT6885_SPI_NUM,

    .plat_features =
#ifdef CONFIG_ARM64_PAN
    PLAT_DEF_ENG | PLAT_ENABLE_PAN,
#else
    PLAT_DEF_ENG,
#endif
    .plat_io_regions = {
        /* .start,      .end */
        { TIMER1_BASE, TIMER1_BASE + TIMER1_BASE_SIZE },
        { RTC_BASE_ADDR, RTC_BASE_ADDR + RTC_BASE_ADDR_SIZE },
        { DX_BASE_CC, DX_BASE_CC + DX_BASE_CC_SIZE },
        { DX_CLOCK_BASE, DX_CLOCK_BASE + DX_CLOCK_BASE_SIZE },
        { SPI0_BASE_ADDR, SPI0_BASE_ADDR + SPI0_BASE_SIZE },
        { SPI1_BASE_ADDR, SPI1_BASE_ADDR + SPI1_BASE_SIZE },
        { SPI5_BASE_ADDR, SPI5_BASE_ADDR + SPI5_BASE_SIZE },
        { GPIO_BASE_ADDR, GPIO_BASE_ADDR + GPIO_BASE_SIAE },
        { IOCFG_RR_BASE_ADDR, IOCFG_RR_BASE_ADDR + IOCFG_RR_BASE_SIAE },
        { FINGERPRINT_XX, FINGERPRINT_XX + FINGERPRINT_XX_SIZE },
        { IOCFG_UFSHCI_BASE, IOCFG_UFSHCI_BASE + IOCFG_UFSHCI_SIZE },
        { TRNG_BASE, TRNG_BASE + TRNG_BASE_SIZE },
        { M4U_BASE0_SEC_PA, M4U_BASE0_SEC_PA + M4U_BASE0_SEC_SIZE },
        { LARB0_BASE_PA, LARB0_BASE_PA + LARB_BASE_SIZE },
        { LARB1_BASE_PA, LARB1_BASE_PA + LARB_BASE_SIZE },
        { LARB2_BASE_PA, LARB2_BASE_PA + LARB_BASE_SIZE },
        { LARB3_BASE_PA, LARB3_BASE_PA + LARB_BASE_SIZE },
        { LARB4_BASE_PA, LARB4_BASE_PA + LARB_BASE_SIZE },
        { LARB5_BASE_PA, LARB5_BASE_PA + LARB_BASE_SIZE },
        { LARB7_BASE_PA, LARB7_BASE_PA + LARB_BASE_SIZE },
        { LARB8_BASE_PA, LARB8_BASE_PA + LARB_BASE_SIZE },
        { LARB9_BASE_PA, LARB9_BASE_PA + LARB_BASE_SIZE },
        { LARB11_BASE_PA, LARB11_BASE_PA + LARB_BASE_SIZE },
        { LARB13_BASE_PA, LARB13_BASE_PA + LARB_BASE_SIZE },
        { LARB14_BASE_PA, LARB14_BASE_PA + LARB_BASE_SIZE },
        { LARB16_BASE_PA, LARB16_BASE_PA + LARB_BASE_SIZE },
        { LARB17_BASE_PA, LARB17_BASE_PA + LARB_BASE_SIZE },
        { LARB18_BASE_PA, LARB18_BASE_PA + LARB_BASE_SIZE },
        { LARB19_BASE_PA, LARB19_BASE_PA + LARB_BASE_SIZE },
        { LARB20_BASE_PA, LARB20_BASE_PA + LARB_BASE_SIZE },
        { DDP_CONFIG, DDP_CONFIG + DDP_BASE_SIZE },
        { DDP_OVL0, DDP_OVL0 + DDP_BASE_SIZE },
        { DDP_OVL0_2L, DDP_OVL0_2L + DDP_BASE_SIZE },
        { DDP_OVL1_2L, DDP_OVL1_2L + DDP_BASE_SIZE },
        { DDP_RDMA0, DDP_RDMA0 + DDP_BASE_SIZE },
        { DDP_RDMA1, DDP_RDMA1 + DDP_BASE_SIZE },
        { DDP_WDMA0, DDP_WDMA0 + DDP_BASE_SIZE },
        { DDP_COLOR0, DDP_COLOR0 + DDP_BASE_SIZE },
        { DDP_CCORRO, DDP_CCORRO + DDP_BASE_SIZE },
        { DDP_AAL0, DDP_AAL0 + DDP_BASE_SIZE },
        { DDP_GAMMA0, DDP_GAMMA0 + DDP_BASE_SIZE },
        { DDP_DITHER0, DDP_DITHER0 + DDP_BASE_SIZE },
        { DDP_DSI0, DDP_DSI0 + DDP_BASE_SIZE },
        { DDP_DPI, DDP_DPI + DDP_BASE_SIZE },
        { DDP_MUTEX, DDP_MUTEX + DDP_BASE_SIZE },
        { DDP_SMI_LARB0, DDP_SMI_LARB0 + DDP_BASE_SIZE },
        { DDP_SMI_LARB1, DDP_SMI_LARB1 + DDP_BASE_SIZE },
        { DDP_SMI_COMMON, DDP_SMI_COMMON + DDP_BASE_SIZE },
        { DDP_RSZ0, DDP_RSZ0 + DDP_BASE_SIZE },
        { DDP_POSTMASK, DDP_POSTMASK + DDP_BASE_SIZE },
        { DDP_PWM0, DDP_PWM0 + DDP_BASE_SIZE },
        { DDP_MIPITX0, DDP_MIPITX0 + DDP_BASE_SIZE },
        { DDP_MIPITX1, DDP_MIPITX1 + DDP_BASE_SIZE },
        { EMI_MPU_BASE, EMI_MPU_BASE + EMI_MPU_BASE_SIZE },
        { 0, 0 } /* this is terminator */
}

};
