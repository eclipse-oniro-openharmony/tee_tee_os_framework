/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: plat_cfg defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-10
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

/* gic */
#define GIC_V3_DIST_PADDR             0x08000000
#define GIC_V3_REDIST_PADDR           0x080A0000
#define GIC_DIST_PAGENUM              16
#define GIC_REDIST_PAGENUM            256
#define GIC_REDIST_NUM                1
#define GIC_REDIST_MEMSIZE            0x20000
#define SPI_NUM                       111
#define TEEOS_MEM_SIZE                0x600000

/* uart addr */
#define UART_ADDR                     0x09040000
#define UART_ADDR_SIZE                0x1000

/* timer reg */
#define OS_TIMER0_REG                 0x20001000
#define OS_TIMER0_REG_SIZE            0x1000
#define OS_TIMER1_REG                 0x20002000
#define OS_TIMER1_REG_SIZE            0x1000
#define OFFSET_PADDR_TO_VADDR         0
#endif
