/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2020-12-29
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

#include <soc_acpu_baseaddr_interface.h>
#include <soc_cpu_baseaddr_interface.h>
#include <global_ddr_map.h>

/* only for burbank */
#define SCSOCID0                        (SOC_ACPU_SCTRL_BASE_ADDR + 0xE00)

#define OFFSET_PADDR_TO_VADDR   0
/* io space for drv_timer */
#ifndef RTC_BASE_ADDR
#define RTC_BASE_ADDR                   SOC_ACPU_RTC1_BASE_ADDR
#endif
#define DX_BASE_CC                      SOC_CPU_CCS_BASE_ADDR
#define RTC_BASE_ADDR_SIZE              0x1000
#define REG_BASE_SCTRL_SIZE             0x1000
#define REG_BASE_PERI_CRG_SIZE          0x1000
#define REG_BASE_PCTRL_SIZE             0x1000
#define REG_BASE_MEDIA1_CRG_SIZE        0x1000
#define TIMER1_BASE_SIZE                0x1000
#define TIMER6_BASE_SIZE                0x1000
#define TIMER7_BASE_SIZE                0x1000

#define SOC_ACPU_DMSS_BASE_ADDR_SIZE         0x30000
#define SOC_ACPU_DMC_0_BASE_ADDR             (SOC_ACPU_DMCPACK0_BASE_ADDR + 0x4000)
#define SOC_ACPU_DMC_1_BASE_ADDR             (SOC_ACPU_DMCPACK1_BASE_ADDR + 0x4000)
/* size: 0x1000 */
#define SOC_ACPU_DMC_BASE_ADDR_SIZE          0x1000
/* 8K */
#define SOC_ACPU_SYS_CNT_BASE_ADDR_SIZE      0x2000
/* 4K */
#define SOC_ACPU_PMC_BASE_ADDR_SIZE          0x1000
/* 1M */
#define SOC_ACPU_HIEPS_BASE_ADDR_SIZE        0x100000
#define SOC_ACPU_IPC_BASE_ADDR_SIZE          0x10000
/* MODEM */
#define EICC_PERI_REGBASE_ADDR               0xFA090000
#define EICC_PERI_REGBASE_ADDR_SIZE          0x8000
#define EICC_MDM0_REGBASE_ADDR               0xF4B00000
#define EICC_MDM0_REGBASE_ADDR_SIZE          0x8000
#define MDM_LPMCU_TCM_ADDR                   0xFFF6C000
#define MDM_LPMCU_TCM_ADDR_SIZE              0x12000


/* SECBOOT */
#define HI_TSP_REG_BASE                      0xF5800000
#define HI_TSP_REG_SIZE                      0x200000

/* DSS reg */
#define DSS_BASE        0xE8400000
#define DSS_BASE_SIZE   0x100000

/* DSS gpio */
#define SOC_ACPU_GPIO0_BASE_ADDR_SIZE     0x1000
#define SOC_ACPU_GPIO1_BASE_ADDR_SIZE     0x1000
#define SOC_ACPU_GPIO2_BASE_ADDR_SIZE     0x1000
#define SOC_ACPU_GPIO3_BASE_ADDR_SIZE     0x1000
#define SOC_ACPU_GPIO23_BASE_ADDR_SIZE     0x1000
#define SOC_ACPU_GPIO25_BASE_ADDR_SIZE     0x1000

#define UART_ADDR                         SOC_ACPU_UART6_BASE_ADDR

#define SOC_ACPU_SPI1_BASE_ADDR_SIZE            0x1000
#define SOC_ACPU_IOMCU_SPI2_BASE_ADDR_SIZE      0x1000
#define SOC_ACPU_SPI3_BASE_ADDR_SIZE            0x1000
#define SOC_ACPU_SPI4_BASE_ADDR_SIZE            0x1000
#define SOC_ACPU_I3C4_BASE_ADDR_SIZE            0x1000
#define SOC_ACPU_AO_IOC_BASE_ADDR_SIZE          0x1000
#define SOC_ACPU_GPIO27_BASE_ADDR_SIZE          0x1000
#define SOC_ACPU_GPIO28_BASE_ADDR_SIZE          0x1000
#define SOC_ACPU_GPIO26_BASE_ADDR_SIZE          0x1000
#define SOC_ACPU_GPIO31_BASE_ADDR_SIZE          0x1000
#define SOC_ACPU_GPIO32_BASE_ADDR_SIZE          0x1000
#define SOC_ACPU_IOMCU_CONFIG_BASE_ADDR_SIZE    0x1000
#define SOC_ACPU_AO_TZPC_BASE_ADDR_SIZE         0x1000

/* io space for cc */
#define DX_BASE_CC_SIZE                      0x100000
/* ddr space for cc */
#define TEEOS_MEM_SIZE              0x3000000
#define SHMEM_SIZE                           0x2000
#define SHMEM_OFFSET                         (TEEOS_MEM_SIZE - SHMEM_SIZE)

#define BURBANK_SPI_NUM             376
#define OFFSET_PADDR_TO_VADDR       0
#define GIC_V3_DIST_ADDR            SOC_ACPU_GIC600_BASE_ADDR
#define GIC_V3_REDIST_ADDR          (SOC_ACPU_GIC600_BASE_ADDR + 0x40000)

#define GIC_DIST_PAGENUM              16
#define GIC_REDIST_PAGENUM            256
#define GIC_REDIST_NUM                1
#define GIC_REDIST_MEMSIZE            0x20000

#define SOC_ACPU_UFS_HCI_OFFSET              0x100000
#define SOC_ACPU_UFS_HCI_BASE_ADDR           (SOC_ACPU_UFS_CFG_BASE_ADDR + SOC_ACPU_UFS_HCI_OFFSET)
#define SOC_ACPU_UFS_HCI_BASE_ADDR_SIZE      0x20000
/* burbank npu register description */
#define TS_DOORBELL_BASE_ADDR                0xE4080000
#define TS_DOORBELL_BASE_ADDR_SIZE           0x80000 /* 512KB */
#define TS_SRAM_BASE_ADDR                    0xE4200000
#define TS_SRAM_BASE_ADDR_SIZE               0x10000 /* 64KB */
#define SMMUV3_SDMA_BASE_ADDR                0xe5f00000
#define SMMUV3_SDMA_BASE_ADDR_SIZE           0x80000
#define L2BUF_BASE_BASE_ADDR                 0xE4800000
/* no l2, one track need define, l2 do not use in sec runtime */
#define L2BUF_BASE_BASE_ADDR_SIZE            0x0
#endif
