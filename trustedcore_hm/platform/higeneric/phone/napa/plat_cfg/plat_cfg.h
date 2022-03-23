/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: plat_cfg defines
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

#include <soc_acpu_baseaddr_interface.h>
#include <global_ddr_map.h>

#define OFFSET_PADDR_TO_VADDR   0
/* io space for drv_timer */
#ifndef RTC_BASE_ADDR
#define RTC_BASE_ADDR                   SOC_ACPU_RTC1_BASE_ADDR
#endif

#define RTC_BASE_ADDR_SIZE              0x1000
#define REG_BASE_SCTRL_SIZE             0x1000
#define REG_BASE_PERI_CRG_SIZE          0x1000
#define REG_BASE_PCTRL_SIZE             0x1000
#define REG_BASE_MEDIA1_CRG_SIZE        0x1000
#define TIMER1_BASE_SIZE                0x1000
#define TIMER6_BASE_SIZE                0x1000
#define TIMER7_BASE_SIZE                0x1000
#define UART_ADDR                     SOC_ACPU_UART6_BASE_ADDR

/* ddr space for cc */
#define TEEOS_MEM_SIZE    0x3000000
#define SHMEM_SIZE                           0x2000
#define SHMEM_OFFSET                         (TEEOS_MEM_SIZE - SHMEM_SIZE)

#define NAPA_GIC3_SECTIONS       2
#define NAPA_SPI_NUM             365
#define OFFSET_PADDR_TO_VADDR       0
#define GIC_V3_DIST_ADDR            SOC_ACPU_GIC600_BASE_ADDR
#define GIC_V3_REDIST_ADDR          (SOC_ACPU_GIC600_BASE_ADDR + 0x40000)
#define GIC_DIST_PAGENUM              16
#define GIC_REDIST_PAGENUM            256
#define GIC_REDIST_NUM                1
#define GIC_REDIST_MEMSIZE            0x20000

#endif
