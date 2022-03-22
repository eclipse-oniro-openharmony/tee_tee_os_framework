/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-03
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H
#define OFFSET_PADDR_TO_VADDR       0x80000000
#define UART_ADDR                 0xE4024000
#define DX_BASE_CC                  0xe4007000 /* size: 0x100000 */
#define DX_BASE_CC_SIZE             0x1000
#define HI_SYSCTRL_BASE_ADDR        0xE0200000 /* size: 0x1000 */
#define HI_SYSCTRL_BASE_ADDR_SIZE   0x1000
#define TIMER1_BASE                 0xedf1f000
#define TIMER1_BASE_SIZE            0x1000
#define TIMER6_BASE                 0xedf1f000
#define TIMER6_BASE_SIZE            0x1000
#define RTC_BASE_ADDR               0xedf06000
#define RTC_BASE_ADDR_SIZE          0x1000
#define REG_BASE_SCTRL              0xFFF0A000
#define REG_BASE_SCTRL_SIZE         0x1000
#define REG_BASE_PERI_CRG           0xFFF35000
#define REG_BASE_PERI_CRG_SIZE      0x1000
#define SYSCTRL_PD_CRG_BASE         0xe4000000
#define SYSCTRL_PD_BASE             0xe4001000
#define IPC_TO_MCU_INT_ADDR         0xE501E000
#define IPC_TO_MCU_INT_ADDR_SIZE    0x1000
#define SYSCTRL_PD_CRG_BASE_SIZE    0x1000
#define SYSCTRL_PD_BASE_SIZE        0x1000
#define TEEOS_MEM_SIZE              0x1000000
#define GIC_V2_DIST_ADDR            0xe9811000
#define GIC_V2_CONTR_ADDR           0xe9812000
#define SPI_NUM                     72
#define SHMEM_SIZE                  0x1000
#define SHMEM_OFFSET                (TEEOS_MEM_SIZE - SHMEM_SIZE)
#endif
