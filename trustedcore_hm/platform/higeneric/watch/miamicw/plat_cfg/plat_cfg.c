/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2020-03
 */
#include <autoconf.h>
#include "plat_cfg.h"
#include "plat_cfg_public.h"
#include <plat_features.h>
#include <hisi_platform.h>
#include "uart_register.h"

#ifndef __aarch64__
#error "Only aarch64 is supported!"
#endif

struct platform_info g_plat_cfg = {
    /* value is assigned in boot_kernel_on_current_cpu function */
    .phys_region_start    = 0,
    .phys_region_size     = TEEOS_MEM_SIZE,
    .uart_addr = UART_ADDR,
    .uart_type = UART_DISABLE_FLAG | PL011_TYPE,
    .shmem_offset = SHMEM_OFFSET,
    .shmem_size           = SHMEM_SIZE,
    /* refer to device/hisi/customize/dtsi/arm64/miamicw/miamicw_memory.dtsi */
    .protected_regions = { { PROTECTED_REGION_START, PROTECTED_REGION_END } },

    .gic_config = {
        .version = GIC_V2_VERSION,
        .v2 = {
            .dist = { GIC_V2_DIST_ADDR, GIC_V2_DIST_ADDR + PAGE_SIZE },
            .contr = { GIC_V2_CONTR_ADDR, GIC_V2_CONTR_ADDR + PAGE_SIZE },
        }
    },

    .spi_num_for_notify = SPI_NUM,

    .plat_features = PLAT_DEF_ENG,
    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions, the first region should be UART6 */
    .plat_io_regions = {
        /* .start,                        .end */
        { TIMER1_BASE,                   TIMER1_BASE + TIMER1_BASE_SIZE },
        { TIMER7_BASE,                   TIMER7_BASE + TIMER7_BASE_SIZE },
        { RTC_BASE_ADDR,                 RTC_BASE_ADDR + RTC_BASE_ADDR_SIZE },
        { REG_BASE_SCTRL,                REG_BASE_SCTRL + REG_BASE_SCTRL_SIZE },
        { REG_BASE_PERI_CRG,             REG_BASE_PERI_CRG + REG_BASE_PERI_CRG_SIZE },
        { TZPC,                          TZPC + TZPC_SIZE },
        { REG_BASE_PCTRL,                REG_BASE_PCTRL + REG_BASE_PCTRL_SIZE },
        { HI_SYSCTRL_BASE_ADDR,          HI_SYSCTRL_BASE_ADDR + HI_SYSCTRL_BASE_ADDR_SIZE },
        { HI_WDT_BASE_ADDR_VIRT,         HI_WDT_BASE_ADDR_VIRT + HI_WDT_BASE_ADDR_VIRT_SIZE },
        { CAMBRICON_X1,                  CAMBRICON_X1 + CAMBRICON_X1_SIZE },
        { CAMBRICON_X2,                  CAMBRICON_X2 + CAMBRICON_X2_SIZE },
        { DX_BASE_CC,                    DX_BASE_CC + DX_BASE_CC_SIZE },
        { DX_BASE_ATLANTA,               DX_BASE_ATLANTA + DX_BASE_ATL_SIZE },
        { HISEE_MBOX_BASE_ADDR,          HISEE_MBOX_BASE_ADDR + HISEE_MBOX_BASE_ADDR_SIZE },
        { HISEE_IPC_BASE_ADDR,           HISEE_IPC_BASE_ADDR + HISEE_IPC_BASE_ADDR_SIZE },
        { HI_IPCM_REGBASE_ADDR,          HI_IPCM_REGBASE_ADDR + HI_IPCM_REGBASE_ADDR_SIZE },
        { HIFI_CFG_BASE_ADDR,            HIFI_CFG_BASE_ADDR + HIFI_CFG_BASE_ADDR_SIZE },
        { HDCP13_ADDR,                   HDCP13_ADDR + HDCP13_ADDR_SIZE },
        { HDCP22_ADDR,                   HDCP22_ADDR + HDCP22_ADDR_SIZE },
        { SOC_ACPU_SCTRL_BASE_ADDR,      SOC_ACPU_SCTRL_BASE_ADDR + SOC_ACPU_SCTRL_BASE_ADDR_SIZE },
        { SOC_ACPU_DMSS_BASE_ADDR,       SOC_ACPU_DMSS_BASE_ADDR + SOC_ACPU_DMSS_BASE_ADDR_SIZE },
        { SOC_ACPU_DMSS_TZMP2_BASE_ADDR, SOC_ACPU_DMSS_TZMP2_BASE_ADDR + SOC_ACPU_DMSS_TZMP2_BASE_ADDR_SIZE },
        { SOC_ACPU_PERI_CRG_BASE_ADDR,   SOC_ACPU_PERI_CRG_BASE_ADDR + SOC_ACPU_PERI_CRG_BASE_ADDR_SIZE },
        { SOC_ACPU_GPIO0_BASE_ADDR,      SOC_ACPU_GPIO0_BASE_ADDR + SOC_ACPU_GPIO0_BASE_ADDR_SIZE },
        { SOC_ACPU_GPIO1_BASE_ADDR,      SOC_ACPU_GPIO1_BASE_ADDR + SOC_ACPU_GPIO1_BASE_ADDR_SIZE },
        { SOC_ACPU_GPIO4_BASE_ADDR,      SOC_ACPU_GPIO4_BASE_ADDR + SOC_ACPU_GPIO4_BASE_ADDR_SIZE },
        { SOC_ACPU_SPI1_BASE_ADDR,       SOC_ACPU_SPI1_BASE_ADDR + SOC_ACPU_SPI1_BASE_ADDR_SIZE },
        { SOC_ACPU_IOC_BASE_ADDR,        SOC_ACPU_IOC_BASE_ADDR + SOC_ACPU_IOC_BASE_ADDR_SIZE },
        { 0, 0 } /* this is terminator */
    }
};
