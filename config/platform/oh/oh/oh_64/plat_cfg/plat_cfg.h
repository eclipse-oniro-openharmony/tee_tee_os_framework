/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
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

#define TEEOS_MEM_SIZE                0x8000000
#define SHMEM_OFFSET                  0x5FF000
#define SHMEM_SIZE                    0x1000

/* uart addr */
#define UART_ADDR                     0x09040000
#define UART_ADDR_SIZE                0x1000

/* timer reg */
#define OS_TIMER0_REG                 0x20001000
#define OS_TIMER0_REG_SIZE            0x1000
#define OS_TIMER1_REG                 0x20002000
#define OS_TIMER1_REG_SIZE            0x1000
#define OFFSET_PADDR_TO_VADDR         0

/* protect region */
#define BL31_PADDR_START              0xe040000
#define BL31_PADDR_END                0xe060000
#endif