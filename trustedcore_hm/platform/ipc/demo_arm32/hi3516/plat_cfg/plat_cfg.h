/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2020-07
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

#define TEEOS_MEM_SIZE              0x6400000
#define UART_ADDR                   0x120a0000
#define TIMER1_BASE                 0x12000000
#define TIMER1_BASE_SIZE            0x1000
#define CPU_CTLR_ADDR               0x12010000
#define CPU_CTLR_SIZE               0x1000
#define SEC_TRNG0_BASE              0x10090000
#define SEC_TRNG0_SIZE              0x1000
#define SEC_CLK_BASE                0x12010000
#define SEC_CLK_SIZE                0x1000
#define SEC_KLAD_BASE               0x10070000
#define SEC_KLAD_SIZE               0x1000
#define SEC_OTP_BASE                0x100B0000
#define SEC_OTP_SIZE                0x1000
#define OFFSET_PADDR_TO_VADDR       0
#define HI3516_SPI_NUM              105
#define GIC_V2_DIST_BASE            0x10301000
#define GIC_V2_CPU_BASE             0x10302000
#define SHMEM_SIZE                  0x1000
#define SHMEM_OFFSET                (TEEOS_MEM_SIZE - SHMEM_SIZE)
#endif
