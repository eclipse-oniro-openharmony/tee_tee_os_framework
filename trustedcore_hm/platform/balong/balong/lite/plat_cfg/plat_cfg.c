/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-06-05
 */
#include "plat_cfg.h"
#include "plat_cfg_public.h"
#include <plat_features.h>
#include "uart_register.h"

struct platform_info g_plat_cfg = {
    /* value is assigned in boot_kernel_on_current_cpu function */
    .phys_region_start    = TRUSTEDCORE_PHY_TEXT_BASE,
    /* 14 MB */
    .phys_region_size     = TEEOS_MEM_SIZE,
    .uart_addr = UART_ADDR,
    .uart_type = UART_DISABLE_FLAG | PL011_TYPE,
    .protected_regions    = { { PROTECTED_REGION_START1, PROTECTED_REGION_END1 } },
    .shmem_offset = SHMEM_OFFSET,
    .shmem_size           = SHMEM_SIZE,

    .gic_config = {
        .version = GIC_V2_VERSION,
        .v2 = {
            .dist = { GIC_V2_DIST_ADDR, GIC_V2_DIST_ADDR + PAGE_SIZE },
            .contr = { GIC_V2_CONTR_ADDR, GIC_V2_CONTR_ADDR + PAGE_SIZE },
        }
    },

    .spi_num_for_notify   = SPI_NUM,
    .plat_features = PLAT_DEF_ENG,
    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions, the first region should be UART6 */
    .plat_io_regions = {
        /* .start,     .end */
        { TIMER1_BASE, TIMER1_BASE + TIMER1_BASE_SIZE },
        { TIMER6_BASE, TIMER6_BASE + TIMER6_BASE_SIZE },
        { RTC_BASE_ADDR, RTC_BASE_ADDR + RTC_BASE_ADDR_SIZE },
        { REG_BASE_SCTRL, REG_BASE_SCTRL + REG_BASE_SCTRL_SIZE },
        { REG_BASE_PERI_CRG, REG_BASE_PERI_CRG + REG_BASE_PERI_CRG_SIZE },
        { REG_BASE_PCTRL, REG_BASE_PCTRL + REG_BASE_PCTRL_SIZE },
        { DX_BASE_CC, DX_BASE_CC + DX_BASE_CC_SIZE },
        { BALONG_PARAM_BASE_ADDR, BALONG_PARAM_BASE_ADDR + BALONG_PARAM_BASE_SIZE },
        { HI_SYSCTRL_BASE_ADDR, HI_SYSCTRL_BASE_ADDR + HI_SYSCTRL_BASE_ADDR_SIZE },
        { HI_NR_SYSCTRL_BASE_ADDR, HI_NR_SYSCTRL_BASE_ADDR + HI_NR_SYSCTRL_BASE_SIZE },
        { HI_EFUSE_SYSCTRL_BASE_ADDR, HI_EFUSE_SYSCTRL_BASE_ADDR + HI_EFUSE_SYSCTRL_BASE_SIZE },
        { HI_IPCM_REGBASE_ADDR, HI_IPCM_REGBASE_ADDR + HI_IPCM_REGBASE_ADDR_SIZE },
        { REG_BASE_SCTRL, REG_BASE_SCTRL + REG_BASE_SCTRL_SIZE },
        /* this is terminator */
        { 0, 0 }
    }
};
