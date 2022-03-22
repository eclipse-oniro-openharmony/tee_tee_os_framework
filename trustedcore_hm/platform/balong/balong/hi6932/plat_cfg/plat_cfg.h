/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Author: chenmou  chenmou1@huawei.com
 * Create: 2020-03
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

#define OFFSET_PADDR_TO_VADDR       0
#define UART_ADDR                   0x90024000
#define DX_BASE_CC                  0x90004000 /* size: 0x100000 */
#define DX_BASE_CC_SIZE             0x1000
#define HI_SYSCTRL_BASE_ADDR        0x80200000 /* size: 0x1000 */
#define HI_SYSCTRL_BASE_ADDR_SIZE   0x1000
#define TIMER1_BASE                 0x2001F000
#define TIMER1_BASE_SIZE            0x1000
#define TIMER6_BASE                 0x2001F000
#define TIMER6_BASE_SIZE            0x1000
#define RTC_BASE_ADDR               0x20006000
#define RTC_BASE_ADDR_SIZE          0x1000
#define REG_BASE_SCTRL              0xFFF0A000 /* SCTRL */
#define REG_BASE_SCTRL_SIZE         0x1000
#define REG_BASE_PERI_CRG           0xFFF35000 /* PERI_CRG */
#define REG_BASE_PERI_CRG_SIZE      0x1000
#define REG_BASE_PCTRL              0xE8A09000
#define REG_BASE_PCTRL_SIZE         0x1000

#define IPC_TO_MCU_INT_BASE_ADDR    0x9101E000
#define IPC_TO_MCU_INT_SIZE         0x1000
#define SYSCTRL_PD_BASE             0x90000000
#define SYSCTRL_PD_SIZE             0x1000
#define SYSCTRL_PD_CRG_BASE         0x90000000
#define SYSCTRL_PD_CRG_BASE_SIZE    0x1000

#define TEEOS_MEM_SIZE              0x1000000
#define GIC_V2_DIST_ADDR            0x96011000
#define GIC_V2_CONTR_ADDR           0x96012000
#define SPI_NUM                     72

#define SYSCTRL_AO_REG_BASE_ADDR    0x20000000
#define SYSCTRL_AO_REG_BASE_SIZE    0x1000

#define SHMEM_SIZE                  0x1000
#define SHMEM_OFFSET                (TEEOS_MEM_SIZE - SHMEM_SIZE)
#endif
