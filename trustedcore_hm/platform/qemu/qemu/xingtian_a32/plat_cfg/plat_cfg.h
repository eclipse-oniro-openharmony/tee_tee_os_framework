/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Author: chenmou  chenmou1@huawei.com
 * Create: 2020-03
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

#define UART_ADDR                 0x09040000
#define UART_ADDR_SIZE            0x1000

#define TEEOS_MEM_SIZE              0x8000000
#define SHMEM_SIZE                  0x1000
#define SHMEM_OFFSET                (TEEOS_MEM_SIZE - SHMEM_SIZE)

#define PLATFORM_FLAG               0x3690
#define GIC_V2_DIST_ADDR            0x08000000
#define GIC_V2_CONTR_ADDR           0x08010000
#define SPI_NUM                     111

#define OS_TIMER0_REG               0x20001000
#define OS_TIMER0_REG_SIZE          0x1000
#define OS_TIMER1_REG               0x20002000
#define OS_TIMER1_REG_SIZE          0x1000
#define OFFSET_PADDR_TO_VADDR       0
#endif
