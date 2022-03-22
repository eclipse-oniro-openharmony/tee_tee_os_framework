/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-03
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

/* teeos size will be transfer from bios */
#define TEEOS_MEM_SIZE             0x0
#define PLATFORM_FLAG              0x3690
#define GIC_V3_DIST_ADDR           0xAA000000
#define GIC_V3_REDIST1_ADDR        0xAA100000
#define GIC_V3_REDIST2_ADDR        0xAE100000
#define GIC_V3_REDIST3_ADDR        0x2000AA100000
#define GIC_V3_REDIST4_ADDR        0x2000AE100000
#define GIC_DIST_PAGENUM           16
#define GIC_REDIST_PAGENUM         2048
#define GIC_REDIST_NUM             4
#define GIC_REDIST_MEMSIZE         0x40000
#define SPI_NUM                    111

#define CERT_KEY_MEM               0xDE000
#define SHMEM_OFFSET               0x500000
#define SHMEM_SIZE                 0x2000
#define OFFSET_PADDR_TO_VADDR      0
#define UART_ADDR                  0x201190000

#define OS_TIMER0_REG              0x94D00000
#define OS_TIMER0_REG_SIZE         0x10000
#define OS_TIMER1_REG              0x94D10000
#define OS_TIMER1_REG_SIZE         0x10000
#define SUBCTRL_REG                0x94000000
#define SUBCTRL_REG_SIZE           0x10000

#define TRNG_BASE_ADDR_CHIP0       0x2010C0000
#define TRNG_ADDR_SIZE_CHIP0       0x10000

#define SEC_BASE                    0x141800000
#define SEC_BASE_SIZE               0x800000
#define PBU_BASE_SIZE               0x8000
#define PEH_BASE_SIZE               0x100000
#define SEC_PBU_REGS_BASE_ADDR      0xD7408000
#define PEH_PF_REGS_BASE_ADDR       0xd7600000
#define HAC_SUBCTRL_REG_ADDR        0x140070000
#define HAC_SUBSCTRL_BASE_SIZE      0x10000

#endif
