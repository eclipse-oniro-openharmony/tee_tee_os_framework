/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Author: chenmou  chenmou1@huawei.com
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

    .spi_num_for_notify   = SPI_NUM,

    /* HM_NOTE: mtk plat is not kirin, plat_features should not include KIRIN */
    .plat_features = PLAT_DEF_ENG,
#ifdef CONFIG_ARM64_PAN
    | PLAT_ENABLE_PAN
#endif

    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions, the first region should be UART6 */
    .plat_io_regions = {
        /* .start,     .end */
        { SYSCTRL_AO_REG_BASE_ADDR, SYSCTRL_AO_REG_BASE_ADDR + SYSCTRL_AO_REG_BASE_SIZE },
        { SYSCTRL_PD_CRG_BASE, SYSCTRL_PD_CRG_BASE + SYSCTRL_PD_CRG_BASE_SIZE },
        { SYSCTRL_PD_BASE, SYSCTRL_PD_BASE + SYSCTRL_PD_SIZE },
        { IPC_TO_MCU_INT_BASE_ADDR, IPC_TO_MCU_INT_BASE_ADDR + IPC_TO_MCU_INT_SIZE },
        { RTC_BASE_ADDR, RTC_BASE_ADDR + RTC_BASE_ADDR_SIZE },
        { REG_BASE_SCTRL, REG_BASE_SCTRL + REG_BASE_SCTRL_SIZE },
        { REG_BASE_PERI_CRG, REG_BASE_PERI_CRG + REG_BASE_PERI_CRG_SIZE },
        { REG_BASE_PCTRL, REG_BASE_PCTRL + REG_BASE_PCTRL_SIZE },
        { DX_BASE_CC, DX_BASE_CC + DX_BASE_CC_SIZE },
        { HI_SYSCTRL_BASE_ADDR, HI_SYSCTRL_BASE_ADDR + HI_SYSCTRL_BASE_ADDR_SIZE },
        { TIMER1_BASE, TIMER1_BASE + TIMER1_BASE_SIZE },
        /* this is terminator */
        { 0, 0 }
    }
};
