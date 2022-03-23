/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2020-03
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

#define PLATFORM_FLAG               0x3751
#define SPI_NUM_FOR_NOTIFY          80
#define TEEOS_MEM_SIZE              0x3000000

#define GICV2_DIST_PADDR            0xF8A01000
#define GICV2_CONTR_PADDR           0xF8A02000

#define UART_ADDR                 0xF8B00000

#define OFFSET_PADDR_TO_VADDR       0

#define TIMER1_BASE      0xF800D000
#define TIMER1_BASE_SIZE 0x1000

#define TIMER7_BASE      0xF800E000
#define TIMER7_BASE_SIZE 0x1000

#ifndef RTC_BASE_ADDR
#define RTC_BASE_ADDR 0xFFF05000
#endif

#define RTC_BASE_ADDR_SIZE     0x1000
#define REG_BASE_SCTRL_SIZE    0x1000
#define REG_BASE_PERI_CRG_SIZE 0x1000
#define REG_BASE_PCTRL_SIZE    0x1000
#define SHMEM_SIZE                    0x1000
#define SHMEM_OFFSET                  (TEEOS_MEM_SIZE - SHMEM_SIZE)

#define PAL_WORKSPACE_MEM_SIZE 0xFF00

#endif
