/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2020-03
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

#define UART_ADDR                     0xFFF02000
/* io space for cc */
#define DX_BASE_CC                    0xF8100000
#define DX_BASE_CC_SIZE               0x100000
#define TEEOS_MEM_SIZE                0x3000000
/* ddr space for cc */
#define SHMEM_SIZE                    0x2000
#define SHMEM_OFFSET                  (TEEOS_MEM_SIZE - SHMEM_SIZE)
/* io space for cc atlanta */
#define DX_BASE_ATLANTA               0xEA980000
#define DX_BASE_ATL_SIZE              0x100000
#define GIC_V3_DIST_ADDR              0xFE800000
#define GIC_V3_REDIST_ADDR            0xFE840000
#define GIC_DIST_PAGENUM              16
#define GIC_REDIST_PAGENUM            256
#define GIC_REDIST_NUM                1
#define GIC_REDIST_MEMSIZE            0x20000
#define SPI_NUM                       376
#define PROTECTED_REGION_START1       0x35B80000
#define PROTECTED_REGION_END1         0x35C81000
#define PROTECTED_REGION_START2       0x35c82000
#define PROTECTED_REGION_END2         0x35C90000

#define OFFSET_PADDR_TO_VADDR   0
/* io space for drv_timer */
#define TIMER1_BASE                     0xFA881000
#define TIMER1_BASE_SIZE                0x1000
#define TIMER6_BASE                     0xFA886000
#define TIMER6_BASE_SIZE                0x1000
#define TIMER7_BASE                     0xFA887000
#define TIMER7_BASE_SIZE                0x1000
#ifndef RTC_BASE_ADDR
#define RTC_BASE_ADDR                   0xFA88D000
#endif
#define RTC_BASE_ADDR_SIZE              0x1000
#define REG_BASE_SCTRL_SIZE             0x1000
#define REG_BASE_PERI_CRG_SIZE          0x1000
#define REG_BASE_PCTRL                  0xFEC3E000
#define REG_BASE_PCTRL_SIZE             0x1000
#define SOC_ACPU_ISP_CORE_CFG_BASE_ADDR 0xE8200000
#define REG_BASE_SCTRL                  0xFA89B000
#define REG_BASE_PERI_CRG               0xFFF05000
#define SOC_ACPU_PERI_CRG_BASE_ADDR     0xFFF05000
#define SOC_ACPU_DMSS_BASE_ADDR         0xFFE80000

/* RTC TIMER PADDR */
#define RTC0_PADDR                      0x09010000
#define RTC0_PADDR_SIZE                 0x1000
#define RTC1_PADDR                      0x09020000
#define RTC1_PADDR_SIZE                 0x1000

/* PMC */
#define PMC_BASE                        0xFFF31000
#define PMC_BASE_SIZE                   0x1000

/* DMC */
#define SOC_ACPU_DMC_0_BASE_ADDR        0xFFE04000
#define SOC_ACPU_DMC_1_BASE_ADDR        0xFFE24000
#define SOC_ACPU_DMC_BASE_ADDR_SIZE       0x100

#define SOC_ACPU_UFS_CFG_BASE_ADDR      0xFAA00000
#define SOC_ACPU_AO_IPC_S_BASE_ADDR     0xFA898000
#define SOC_ACPU_TIMER10_BASE_ADDR      0xFEC2D000
#define SOC_ACPU_PERI_CRG_BASE_ADDR_SIZE  0x1000

#define SOC_ACPU_IPC_NS_BASE_ADDR       0xFED01000
#define SOC_ACPU_IPC_BASE_ADDR          0xFED00000

/* DSS */
#define DSS_BASE                          0xE8400000
#define DSS_BASE_SIZE                     0x100000
#define NOC_DSS_BASE                      0xE86C0000
#define NOC_DSS_BASE_SIZE                 0x1000

/* GPIO0 */
#define SOC_ACPU_GPIO9_BASE_ADDR          0xFEC1B000
#define SOC_ACPU_GPIO9_BASE_ADDR_SIZE     0x1000
#define SOC_ACPU_GPIO28_BASE_ADDR         0xFA8B0000
#define SOC_ACPU_GPIO28_BASE_ADDR_SIZE    0x1000

#define SOC_ACPU_GPIO0_BASE_ADDR          0xFEC12000
#define SOC_ACPU_GPIO0_BASE_ADDR_SIZE     0x1000
#define SOC_ACPU_GPIO5_BASE_ADDR          0xFEC17000
#define SOC_ACPU_GPIO5_BASE_ADDR_SIZE     0x1000

/* MMBUF */
#define PCTRL_BASE                        REG_BASE_PCTRL
#define PCTRL_BASE_SIZE                   REG_BASE_PCTRL_SIZE
#define MMBUF_CFG_BASE                    0xFFF02000
#define MMBUF_CFG_BASE_SIZE               0x1000

/* io space for tui */
#define SOC_ACPU_DMSS_BASE_ADDR_SIZE      0x30000

/* GPIO28,GPIO1_SE,AO_IOC */
#define GPIO_SPI                          0xFFF10000
#define GPIO_SPI_SIZE                     0x20000

/* size: 0x1000 */
#define TZPC                              0xFEC3C000
#define TZPC_SIZE                         0x1000
#define AO_TZPC                           0xFA89E000
#define AO_TZPC_SIZE                      0x1000

/* SOC IO BASE_ADDR */
#define SOC_CPU_IOMCU_CONFIG_BASE_ADDR      0xFA87E000
#define SOC_CPU_IOMCU_CONFIG_BASE_ADDR_SIZE 0x1000
#define SOC_ACPU_IOMCU_SPI2_BASE_ADDR       0xFA868000
#define SOC_ACPU_IOMCU_SPI2_BASE_ADDR_SIZE  0x1000
#define SOC_ACPU_IOMCU_DMAC_BASE_ADDR       0xFA877000
#define SOC_ACPU_IOMCU_DMAC_BASE_ADDR_SIZE  0x1000

/* SOC GP BASE_ADDR */
#define SOC_ACPU_GPIO0_BASE_ADDR_SIZE       0x1000
#define SOC_ACPU_GPIO6_BASE_ADDR_SIZE       0x1000
#define SOC_ACPU_GPIO25_BASE_ADDR_SIZE      0x1000
#define SOC_ACPU_GPIO4_BASE_ADDR_SIZE       0x1000

/* SOC SCTRL BASE_ADDR */
#define SOC_ACPU_SCTRL_BASE_ADDR            0xFA89B000
#define SOC_ACPU_SCTRL_BASE_ADDR_SIZE       0x1000
#define SOC_ACPU_I2C7_BASE_ADDR             0xFA04F000
#define SOC_ACPU_I2C7_BASE_ADDR_SIZE        0x1000
#define SOC_ACPU_I3C4_BASE_ADDR             0xFA050000
#define SOC_ACPU_I3C4_BASE_ADDR_SIZE        0x1000

/* SOC SPI BASE_ADDR */
#define SOC_ACPU_SPI1_BASE_ADDR             0xFA048000
#define SOC_ACPU_SPI1_BASE_ADDR_SIZE        0x1000
#define SOC_ACPU_SPI3_BASE_ADDR             0xFA89F000
#define SOC_ACPU_SPI3_BASE_ADDR_SIZE        0x1000
#define SOC_ACPU_SPI4_BASE_ADDR             0xFA049000
#define SOC_ACPU_SPI4_BASE_ADDR_SIZE        0x1000

/* SOC GPIO2 BASE_ADDR */
#define SOC_ACPU_GPIO2_BASE_ADDR            0xFEC14000
#define SOC_ACPU_GPIO2_BASE_ADDR_SIZE       0x1000
#define SOC_ACPU_GPIO26_BASE_ADDR           0xFA8AE000
#define SOC_ACPU_GPIO26_BASE_ADDR_SIZE      0x1000
#define SOC_ACPU_GPIO27_BASE_ADDR           0xFA8AF000
#define SOC_ACPU_GPIO27_BASE_ADDR_SIZE      0x1000
#define SOC_ACPU_GPIO28_BASE_ADDR           0xFA8B0000
#define SOC_ACPU_GPIO28_BASE_ADDR_SIZE      0x1000

#define SOC_ACPU_GPIO22_BASE_ADDR           0xFA8AA000
#define SOC_ACPU_GPIO22_BASE_ADDR_SIZE      0x1000
#define SOC_ACPU_GPIO23_BASE_ADDR           0xFA8AB000
#define SOC_ACPU_GPIO23_BASE_ADDR_SIZE      0x1000
#define SOC_ACPU_GPIO24_BASE_ADDR           0xFA8AC000
#define SOC_ACPU_GPIO24_BASE_ADDR_SIZE      0x1000

/* SOC AO BASE_ADDR */
#define SOC_ACPU_AO_IOC_BASE_ADDR           0xFA89C000
#define SOC_ACPU_AO_IOC_BASE_ADDR_SIZE      0x1000

#define SOC_ACPU_IOC_BASE_ADDR              0xFED02000
#define SOC_ACPU_IOC_BASE_ADDR_SIZE         0x1000
#define SOC_CPU_IOMCU_CONFIG_BASE_ADDR      0xFA87E000
#define SOC_CPU_IOMCU_CONFIG_BASE_ADDR_SIZE 0x1000
#define SOC_ACPU_IOMCU_SPI2_BASE_ADDR       0xFA868000
#define SOC_ACPU_IOMCU_SPI2_BASE_ADDR_SIZE  0x1000
#define SOC_ACPU_IOMCU_DMAC_BASE_ADDR       0xFA877000
#define SOC_ACPU_IOMCU_DMAC_BASE_ADDR_SIZE  0x1000
#define SOC_ACPU_GPIO1_SE_BASE_ADDR         0xFA8A1000
#define SOC_ACPU_GPIO1_SE_BASE_ADDR_SIZE    0x1000

/* HIFI */
#define HIFI_CFG_BASE_ADDR                   0xFA54E000
#define HIFI_CFG_DMMU_BASE_ADDR              0xFA547000
#define HIFI_CFG_DMMU_BASE_SIZE              0x1000
#define HIFI_CFG_BASE_ADDR_SIZE              0x1000

/* ISP */
#define CRG_BASE                             0xFFF35000
#define SOC_ACPU_ISP_CORE_CFG_BASE_ADDR_SIZE 0x200000

#define CRG_BASE_SIZE                        0x1000
/* MEDI */
#define MEDIA_CRG_BASE_ADDR                  0xE8601000
#define MEDIA_CRG_BASE_ADDR_SIZE             0x1000

/* SOCP */
#define SOCP_BASE_ADDR                       0xfa0a0000
#define SOCP_BASE_ADDR_SIZE                  0x1000

/* SECBOOT */
#define HI_SYSCTRL_BASE_ADDR                 0xE0200000
#define HI_SYSCTRL_BASE_ADDR_SIZE            0x1000
#define HI_WDT_BASE_ADDR_VIRT                0xE0201000
#define HI_WDT_BASE_ADDR_VIRT_SIZE           0x1000

#define SOC_ACPU_SCTRL_BASE_ADDR_SIZE        0x1000
#define SECBOOT_XX                           0xFDF0F000
#define SECBOOT_XX_SIZE                      0x1000

#define SCSOCID0                             (REG_BASE_SCTRL + 0xE00)

/* Cambricon */
#define CAMBRICON_X1                         0xFF400000
#define CAMBRICON_X1_SIZE                    0x100000
#define CAMBRICON_X2                         0xFF500000
#define CAMBRICON_X2_SIZE                    0x100000

/* IOMCU */
#define SOC_ACPU_IOMCU_SPI2_BASE_ADDR_SIZE   0x1000
#define SOC_ACPU_IOMCU_CONFIG_BASE_ADDR_SIZE 0x1000
#define SOC_ACPU_IOMCU_DMAC_BASE_ADDR_SIZE   0x1000

/* io space for hisee */
#define HISEE_MBOX_BASE_ADDR                 0xF0E20000
#define HISEE_MBOX_BASE_ADDR_SIZE            0x4000
#define HISEE_IPC_BASE_ADDR                  0xF0E30000
#define HISEE_IPC_BASE_ADDR_SIZE             0x1000

/* MODEM */
#define HI_IPCM_REGBASE_ADDR                 0xFA080000
#define HI_IPCM_REGBASE_ADDR_SIZE            0x1000

/* SENSORHUB_IPC_BASE_ADDR */
#define SENSORHUB_IPC_BASE_ADDR              0xFA898000
#define SENSORHUB_IPC_BASE_ADDR_SIZE         0x1000

/* io space for HDCP */
#define HDCP13_ADDR                          0xFF340000

/* BASE_ADDR 0x1000 */
#define HDCP13_ADDR_SIZE                     0x4000
#define HDCP22_ADDR                          0xFF351000
#define HDCP22_ADDR_SIZE                     0x2000
#define SMMUV3_SDMA_BASE_ADDR                0xe5f00000
#define SMMUV3_SDMA_BASE_ADDR_SIZE           0x80000

/* DRM */
#define SOC_ACPU_VDEC_BASE_ADDR              0xE9200000
#define SOC_ACPU_VDEC_BASE_ADDR_SIZE         0x100000

/* io space for npu */
#define SOC_ACPU_VENC_BASE_ADDR_SIZE         0x100000
#define SOC_ACPU_UFS_CFG_BASE_ADDR_SIZE      0x20000
#define SOC_ACPU_AO_IPC_S_BASE_ADDR_SIZE     0x1000
#define SOC_ACPU_TIMER10_BASE_ADDR_SIZE      0x1000
#define SOC_ACPU_IPC_NS_BASE_ADDR_SIZE       0x1000
#define SOC_ACPU_IPC_BASE_ADDR_SIZE          0x1000

/* kirin990 cs  npu register description */
#define TS_DOORBELL_BASE_ADDR                0xE4080000
#define TS_DOORBELL_BASE_ADDR_SIZE           0x80000 /* 512KB */
#define L2BUF_BASE_BASE_ADDR                 0xE4800000
#define L2BUF_BASE_BASE_ADDR_SIZE            0x100000 /* size: 1MB */
#define TS_SRAM_BASE_ADDR                    0xE4200000
#define TS_SRAM_BASE_ADDR_SIZE               0x10000 /* 64KB */

/* Fingerprint */
#define RESET_PIN_GPIO_ADDR                  0xFFF0F000
#define RESET_PIN_GPIO_ADDR_SIZE             0x1000

/* coresight etf2: for etf0,1 */
#define SOC_ACPU_CSSYS_APB_BASE_ADDR_SIZE    0x100000
/* Mate10 Pro THP */
#define SOC_ACPU_I2C7_BASE_ADDR_SIZE 0x1000

#endif
