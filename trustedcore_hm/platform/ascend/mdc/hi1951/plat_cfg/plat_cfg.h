/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-03
 */
#ifndef PLAT_CFG_HI1951_H
#define PLAT_CFG_HI1951_H
#define UART_ADDR                   0x840C0000
#define PROTECTED_REGION_START1     0x04000000
#define PROTECTED_REGION_END1       0x04400000
#define GIC_V3_DIST_ADDR            0x85000000
#define GIC_V3_REDIST1_ADDR         0x85100000
#define GIC_V3_REDIST2_ADDR         0x8085100000
#define GIC_DIST_PAGENUM            16
#define GIC_REDIST_PAGENUM          1024
#define GIC_REDIST_NUM              2
#define GIC_REDIST_MEMSIZE          0x40000
#define SPI_NUM                     300
#define TEEOS_MEM_SIZE              0x6000000

/* timer */
#define OS_TIMER0_REG               0x8B300000
#define OS_TIMER0_REG_SIZE          0x10000
#define OS_TIMER1_REG               0x8B310000
#define OS_TIMER1_REG_SIZE          0x10000
#define SUBCTRL_REG                 0x880C0000
#define SUBCTRL_REG_SIZE            0x10000

/* sec and trng */
#define SEC_BASE_ADDR               0x8A800000
#define SEC_BASE_SIZE               0x800000
#define PEH_PF_REGS_BASE_ADDR       0xD7700000
#define PEH_BASE_SIZE               0x100000
#define SC_SEC_PBU_REGS_BASE_ADDR   0xD7410000
#define PBU_BASE_SIZE               0x8000
#define HAC_SUBCTRL_REG_ADDR        0x880C0000
#define HAC_SUBSCTRL_BASE_SIZE      0x10000
#define CFG_DISP_BASE_ADDR          0x88060000
#define CFG_DISP_SIZE               0x8000
#define TRNG_BASE_ADDR              0x88110000
#define TRNG_BASE_SIZE              0x10000
#define OFFSET_PADDR_TO_VADDR       0
#define SHMEM_SIZE                  0x1000
#define SHMEM_OFFSET                (TEEOS_MEM_SIZE - SHMEM_SIZE)
/* scmi */
#define SCMI0_REG_BASE              0x84080000
#define SCMI0_REG_ADDR_SIZE         (1024 * 8)  /* 8K size */

#define SFC0_REG_BASE_ADDR          0x84100000
#define P2_CHIPOFFSET              0x8000000000
#define SFC1_REG_BASE_ADDR          (P2_CHIPOFFSET + SFC0_REG_BASE_ADDR)
#define SFC_REG_SIZE                (1024 * 8)

#define SFC0_FLASH_MEM_BASE_ADDR    0x90000000
#define SFC1_FLASH_MEM_BASE_ADDR    (P2_CHIPOFFSET + SFC0_FLASH_MEM_BASE_ADDR)
#define SFC_FLASH_MEM_SIZE          (16 * 1024 * 1024)

#define SYSCTRL_REG_BASE             0x80000000
#define SYSCTRL_REG_SIZE             (1024 * 512)
#define EFUSE0_CTRL_BASE             0x81260000
#define EFUSE0_CTRL_SIZE             (1024 * 64)
#define EFUSE1_CTRL_BASE             0x81270000
#define EFUSE1_CTRL_SIZE             (1024 * 64)

/* lp timer */
#define LOWPOWER_TIMER              0x84820000
#define LOWPOWER_TIMER_SIZE         0x10000 /* 64k size */

/* SRAM */
#define SRAM0_CTRL_BASE_ADDR        (0xC6F00000 + 0x4D000)
#define SRAM1_CTRL_BASE_ADDR        (P2_CHIPOFFSET + SRAM0_CTRL_BASE_ADDR)
#define SRAM_CTRL_SIZE              0x23000

#endif
