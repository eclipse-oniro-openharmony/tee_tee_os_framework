/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2020-03
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

#define PLATFORM_FLAG      0x3516
#define SPI_NUM_FOR_NOTIFY 75
#define TEEOS_MEM_SIZE     0x1000000

#define GICV2_DIST_PADDR  0xF1001000
#define GICV2_CONTR_PADDR 0xF1002000

#define UART_ADDR      0xF8B00000

#define OFFSET_PADDR_TO_VADDR 0xE0000000

#define TIMER1_BASE_PADDR  0xF8008000
#define TIMER1_BASE      (TIMER1_BASE_PADDR - OFFSET_PADDR_TO_VADDR)
#define TIMER1_BASE_SIZE 0x1000
#define TIMER7_BASE_PADDR  0xF8009000
#define TIMER7_BASE      (TIMER7_BASE_PADDR - OFFSET_PADDR_TO_VADDR)
#define TIMER7_BASE_SIZE 0x1000

#ifndef RTC_BASE_ADDR
#define RTC_BASE_ADDR    0xFFF05000
#endif

#define RTC_BASE_ADDR_SIZE 0x1000

#endif
