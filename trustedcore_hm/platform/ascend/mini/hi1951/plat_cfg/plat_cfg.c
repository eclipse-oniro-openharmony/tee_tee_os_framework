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

    /* To config, set TRUSTEDCORE_PHY_TEXT_BASE in common/var.mk
     * value is assigned in boot_kernel_on_current_cpu function */
    .phys_region_start = 0,

    .phys_region_size = TEEOS_MEM_SIZE,

    .uart_addr = UART_ADDR,

    .uart_type = UART_DISABLE_FLAG | PL011_TYPE,

    .shmem_offset = SHMEM_OFFSET,

    .shmem_size = SHMEM_SIZE,

    .protected_regions = {{BL31_START_ADDR, BL31_END_ADDR}},

    .plat_features =
    PLAT_DEF_ENG
#ifdef CONFIG_ARM64_PAN
    | PLAT_ENABLE_PAN
#endif
    ,

    .gic_config = {
        .version = GIC_V3_VERSION,
        .v3 = {
            .dist = { GIC_DIST_PADDR, GIC_DIST_PADDR + GIC_DIST_PAGENUM * PAGE_SIZE },
            .redist_num = GIC_REDIST_NUM,
            .redist_stride = GIC_REDIST_MEMSIZE,
            .redist = {
                { GIC_V3_REDIST1_ADDR, GIC_V3_REDIST1_ADDR + GIC_REDIST_PAGENUM * PAGE_SIZE },
                { GIC_V3_REDIST2_ADDR, GIC_V3_REDIST2_ADDR + GIC_REDIST_PAGENUM * PAGE_SIZE }
            }
        }
    },

    .spi_num_for_notify = SPI_NUM,
    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions */
    .plat_io_regions = {
        /* the second region should be freerunning timer */
        { OS_TIMER0_REG,                        OS_TIMER0_REG + OS_TIMER0_REG_SIZE },
        /* the third region should be trng for random gen */
        { TRNG_BASE_ADDR,                       TRNG_BASE_ADDR + TRNG_BASE_SIZE },
        { OS_TIMER1_REG,                        OS_TIMER1_REG + OS_TIMER1_REG_SIZE },
        { SUBCTRL_REG,                          SUBCTRL_REG + SUBCTRL_REG_SIZE },
        { SEC_BASE_ADDR,                        SEC_BASE_ADDR + SEC_BASE_SIZE },
        { PEH_PF_REGS_BASE_ADDR,                PEH_PF_REGS_BASE_ADDR + PEH_BASE_SIZE },
        { SC_SEC_PBU_REGS_BASE_ADDR,            SC_SEC_PBU_REGS_BASE_ADDR + PBU_BASE_SIZE },
        { HAC_SUBCTRL_REG_ADDR,                 HAC_SUBCTRL_REG_ADDR + HAC_SUBSCTRL_BASE_SIZE },
        { CFG_DISP_BASE_ADDR,                   CFG_DISP_BASE_ADDR + CFG_DISP_SIZE },
        { SCMI0_REG_BASE,                       SCMI0_REG_BASE + SCMI0_REG_ADDR_SIZE },
        { SCMI0_REG_BASE_P1,                    SCMI0_REG_BASE_P1 + SCMI0_REG_ADDR_SIZE },
        { SYSTEM_COUNTER,                       SYSTEM_COUNTER + SYSCOUNTER_SIZE },
        { SFC0_REG_BASE_ADDR,                   SFC0_REG_BASE_ADDR + SFC_REG_SIZE },
        { SFC1_REG_BASE_ADDR,                   SFC1_REG_BASE_ADDR + SFC_REG_SIZE },
        { SFC0_FLASH_MEM_BASE_ADDR,             SFC0_FLASH_MEM_BASE_ADDR + SFC_FLASH_MEM_SIZE },
        { SFC1_FLASH_MEM_BASE_ADDR, 		    SFC1_FLASH_MEM_BASE_ADDR + SFC_FLASH_MEM_SIZE },
        { SYSCTRL_REG_BASE,                     SYSCTRL_REG_BASE + SYSCTRL_REG_SIZE },
        { SYSCTRL1_REG_BASE,          			SYSCTRL1_REG_BASE + SYSCTRL1_REG_SIZE },
        { EFUSE0_CTRL_BASE,                     EFUSE0_CTRL_BASE + EFUSE0_CTRL_SIZE },
        { EFUSE0_CTRL_P1_BASE,          		EFUSE0_CTRL_P1_BASE + EFUSE0_CTRL_SIZE },
        { EFUSE1_CTRL_BASE,                     EFUSE1_CTRL_BASE + EFUSE1_CTRL_SIZE },
        { EFUSE1_CTRL_P1_BASE,          		EFUSE1_CTRL_P1_BASE + EFUSE1_CTRL_SIZE },
        { SRAM0_CTRL_BASE_ADDR,                 SRAM0_CTRL_BASE_ADDR + SRAM_CTRL_SIZE },
        { SRAM1_CTRL_BASE_ADDR, 				SRAM1_CTRL_BASE_ADDR + SRAM_CTRL_SIZE },
        { 0, 0 } /* this is terminator */
}

};
