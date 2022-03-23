/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-03
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H
#define UART_ADDR                   0x10107000
#define TIMER0_BASE                 0x10102000
#define TIMER1_BASE_SIZE            0x1000
#define RTC_BASE_ADDR_SIZE          0x1000
#define REG_BASE_SCTRL_SIZE         0x1000
#define REG_BASE_PERI_CRG_SIZE      0x1000
#define REG_BASE_PCTRL_SIZE         0x1000
#define TEEOS_MEM_SIZE              0x1000000
#define SHMEM_SIZE                  0x1000
#define SHMEM_OFFSET                (TEEOS_MEM_SIZE - SHMEM_SIZE)

#define GIC_DIST_PADDR              0x15001000
#define GIC_CPU_PADDR               0x15002000

#define SEC_TRNG0_BASE              0x1010F000
#define SEC_TRNG0_SIZE              0x1000
#define SEC_KDF0_BASE               0x10110000
#define SEC_KDF0_SIZE               0x1000
#define SEC_PKE_BASE                0x10770000
#define SEC_PKE_SIZE                0x10000
#define SEC_SEC0_BASE               0x15220000
#define SEC_SEC0_SIZE               0x10000
#define HI_SEC_REG_CRG_DIO_BASE     0x14880000
#define HI_SEC_REG_CRG_DIO_SIZE     0x80000
#define ROUTER_SPI_NUM              32
#define OFFSET_PADDR_TO_VADDR       0
#endif
