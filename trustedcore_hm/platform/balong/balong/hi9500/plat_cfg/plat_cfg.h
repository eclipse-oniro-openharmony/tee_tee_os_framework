/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-03
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H
#define PROTECTED_REGION_START1     0x1200000
#define PROTECTED_REGION_END1       0x1400000
#define OFFSET_PADDR_TO_VADDR       0
#define UART_ADDR                   0xE4024000
#define DX_BASE_CC                  0xE4006000 /* size: 0x100000 */
#define DX_BASE_CC_SIZE             0x100000
#define HI_SYSCTRL_BASE_ADDR        0xE0200000 /* size: 0x1000 */
#define HI_SYSCTRL_BASE_ADDR_SIZE   0x1000
#define TIMER1_BASE                 0xEDF1F000
#define TIMER1_BASE_SIZE            0x1000
#define TIMER6_BASE                 0xEDF1F000
#define TIMER6_BASE_SIZE            0x1000
#define RTC_BASE_ADDR               0xEDF06000
#define RTC_BASE_ADDR_SIZE          0x1000
#define REG_BASE_SCTRL              0xEDF00000 /* SCTRL */
#define REG_BASE_SCTRL_SIZE         0x1000
#define REG_BASE_PERI_CRG           0xE4000000 /* PERI_CRG */
#define REG_BASE_PERI_CRG_SIZE      0x1000
#define REG_BASE_PCTRL              0xFE02E000
#define REG_BASE_PCTRL_SIZE         0x1000
#define BALONG_PARAM_BASE_ADDR      0x9FF000
#define BALONG_PARAM_BASE_SIZE      0x1000
#define HI_NR_SYSCTRL_BASE_ADDR     0xF8000000
#define HI_NR_SYSCTRL_BASE_SIZE     0x1000
#define HI_EFUSE_SYSCTRL_BASE_ADDR  0xEDF07000
#define HI_EFUSE_SYSCTRL_BASE_SIZE  0x1000
#define HI_IPCM_REGBASE_ADDR        0xE501F000
#define HI_IPCM_REGBASE_ADDR_SIZE   0x1000
#define TEEOS_MEM_SIZE              0xE00000
#define SHMEM_SIZE                  0x1000
#define SHMEM_OFFSET                (TEEOS_MEM_SIZE - SHMEM_SIZE)

#define GIC_V2_DIST_ADDR            0xE6F11000
#define GIC_V2_CONTR_ADDR           0xE6F12000
#define SPI_NUM                     72
#define PROTECTED_REGION_START1     0x1200000
#define PROTECTED_REGION_END1       0x1400000

#endif
