/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: plat_cfg defines
 * Author: hemuyang1@huawei.com
 * Create: 2021-03-09
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

#define TEEOS_MEM_SIZE             0x2000000
#define GIC_V3_DIST_ADDR           0xF6800000
#define GIC_V3_REDIST_ADDR         0xF6900000
#define SPI_NUM                    366
#define GIC_DIST_PAGENUM           16
#define GIC_REDIST_PAGENUM         256
#define GIC_REDIST_NUM             1
#define GIC_REDIST_MEMSIZE         0x40000

#define SHMEM_SIZE                 0x1000
#define SHMEM_OFFSET               (TEEOS_MEM_SIZE - SHMEM_SIZE)
#define OFFSET_PADDR_TO_VADDR      0
#define UART_ADDR                  0xF0200000

#define OS_TIMER0_REG       0xF0190000
#define OS_TIMER0_REG_SIZE          0x10000
#define OS_TIMER1_REG       0xF01A0000
#define OS_TIMER1_REG_SIZE          0x10000
#define SUBCTRL_REG         0xF0000000
#define SUBCTRL_REG_SIZE            0x10000

#define TRNG_BASE_ADDR_CHIP0 0xFB100000
#define TRNG_ADDR_SIZE_CHIP0 0x10000

#endif
