/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-07-28
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

/* UART */
#define UART_ADDR        0x11002000 /* UART0 */

/* io space for drv_timer */
#define TIMER1_BASE            0x1000A000
#define TIMER1_BASE_SIZE       0x1000
#define RTC_BASE_ADDR          0x1000D000  /* PMIF_SPI_BASE */
#define RTC_BASE_ADDR_SIZE     0x1000

/* fingerprint */
#define FINGERPRINT_XX              0xFDF06000
#define FINGERPRINT_XX_SIZE         0x1000

/* io space for cc */
#define DX_BASE_CC                   0x10210000
#define DX_BASE_CC_SIZE              0x100000
#define DX_CLOCK_BASE                0x10001000
#define DX_CLOCK_BASE_SIZE           0x1000
#define SPI0_BASE_ADDR               0x1100A000
#define SPI0_BASE_SIZE               0x1000
#define SPI1_BASE_ADDR               0x11010000
#define SPI1_BASE_SIZE               0x1000
#define SPI5_BASE_ADDR               0x11019000
#define SPI5_BASE_SIZE               0x1000
#define GPIO_BASE_ADDR               0x10005000
#define GPIO_BASE_SIAE               0x1000
#define IOCFG_RM_BASE_ADDR           0x10002800
#define IOCFG_RM_BASE_SIAE           0x1000

/* ddr space for cc */
#define TEEOS_MEM_SIZE              0
#define SHMEM_SIZE                  0x1000
#define SHMEM_OFFSET                0

#define PROTECTED_REGION_START1       0x47D80000
#define PROTECTED_REGION_END1         0x47DC0000
#define PROTECTED_REGION_START2       0x4CE00000
#define PROTECTED_REGION_END2         0x4CE60000
#define PLATFORM_FLAG                 0x6765

#define GIC_V3_DIST_ADDR              0x0C000000
#define GIC_V3_REDIST_ADDR            0x0C040000
#define GIC_DIST_PAGENUM              16
#define GIC_REDIST_PAGENUM            256
#define GIC_REDIST_NUM                1
#define GIC_REDIST_MEMSIZE            0x20000
#define MT6768_SPI_NUM                329
#define MT6768_GIC3_SECTIONS          3
#define OFFSET_PADDR_TO_VADDR         0
#endif
