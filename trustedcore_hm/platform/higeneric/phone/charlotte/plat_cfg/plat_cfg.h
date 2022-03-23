/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2020-12-08
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

#include <soc_acpu_baseaddr_interface.h>

/* io space for drv_timer */
#ifndef RTC_BASE_ADDR
#define RTC_BASE_ADDR                   SOC_ACPU_RTC1_BASE_ADDR
#endif
#define RTC_BASE_ADDR_SIZE              0x1000
#define REG_BASE_SCTRL_SIZE             0x1000
#define REG_BASE_PERI_CRG_SIZE          0x1000
#define REG_BASE_PCTRL_SIZE             0x1000
#define TIMER1_BASE_SIZE                0x1000
#define TIMER6_BASE_SIZE                0x1000
#define TIMER7_BASE_SIZE                0x1000
#define UART_ADDR                       SOC_ACPU_UART6_BASE_ADDR

#define OFFSET_PADDR_TO_VADDR           0
/* you should make sure that PLATFORM_FLAG is different from any mtk phone */
#define PLATFORM_FLAG                   0x36B0
/* IPC */
#define SOC_ACPU_IPC_BASE_ADDR_SIZE     0x10000
/* ddr space for cc */
#define TEEOS_MEM_SIZE                       0x3000000
#define SHMEM_SIZE                           0x2000
#define SHMEM_OFFSET                         (TEEOS_MEM_SIZE - SHMEM_SIZE)
#define GIC_V3_DIST_ADDR                     SOC_ACPU_GIC600_BASE_ADDR
#define GIC_V3_REDIST_ADDR                   (SOC_ACPU_GIC600_BASE_ADDR + 0x40000)
#define GIC_DIST_PAGENUM                     16
#define GIC_REDIST_PAGENUM                   256
#define GIC_REDIST_NUM                       1
#define GIC_REDIST_MEMSIZE                   0x20000
#define SPI_NUM                              354 /* <platform>_trustedcore_es.dtsi */

#endif
