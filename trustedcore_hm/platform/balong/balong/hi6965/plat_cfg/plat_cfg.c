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
    .phys_region_start    = TRUSTEDCORE_PHY_TEXT_BASE,
    /* 16 MB */
    .phys_region_size     = TEEOS_MEM_SIZE,
    .uart_addr = UART_ADDR,
    .uart_type = UART_DISABLE_FLAG | PL011_TYPE,
    .shmem_offset = SHMEM_OFFSET,
    .shmem_size           = SHMEM_SIZE,

    .gic_config = {
        .version = GIC_V2_VERSION,
        .v2 = {
            .dist = { GIC_V2_DIST_ADDR, GIC_V2_DIST_ADDR + PAGE_SIZE },
            .contr = { GIC_V2_CONTR_ADDR, GIC_V2_CONTR_ADDR + PAGE_SIZE },
        }
    },

    .spi_num_for_notify  = SPI_NUM,

#ifdef CONFIG_ARM64_PAN
    .plat_features = PLAT_DEF_ENG | PLAT_ENABLE_PAN,
#else
    .plat_features = PLAT_DEF_ENG,
#endif
    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions, the first region should be UART6 */
    .plat_io_regions = {
        /* .start,     .end */
        { SYSCTRL_PD_CRG_BASE, SYSCTRL_PD_CRG_BASE + SYSCTRL_PD_CRG_BASE_SIZE },
        { SYSCTRL_PD_BASE, SYSCTRL_PD_BASE + SYSCTRL_PD_BASE_SIZE },
        { IPC_TO_MCU_INT_ADDR, IPC_TO_MCU_INT_ADDR + IPC_TO_MCU_INT_ADDR_SIZE },
        { RTC_BASE_ADDR, RTC_BASE_ADDR + RTC_BASE_ADDR_SIZE },
        { REG_BASE_SCTRL, REG_BASE_SCTRL + REG_BASE_SCTRL_SIZE },
        { REG_BASE_PERI_CRG, REG_BASE_PERI_CRG + REG_BASE_PERI_CRG_SIZE },
        { DX_BASE_CC, DX_BASE_CC + DX_BASE_CC_SIZE },
        { HI_SYSCTRL_BASE_ADDR, HI_SYSCTRL_BASE_ADDR + HI_SYSCTRL_BASE_ADDR_SIZE },
        { TIMER1_BASE, TIMER1_BASE + TIMER1_BASE_SIZE },
        /* this is terminator */
        { 0, 0 }
    }
};
