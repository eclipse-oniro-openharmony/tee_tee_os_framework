/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2020-03
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

#define UART_ADDR                    0xFFF32000
#define SOC_ACPU_SPI1_BASE_ADDR_SIZE 0x1000
#define SOC_ACPU_GPIO1_BASE_ADDR_SIZE 0x1000
#define SOC_ACPU_IOC_BASE_ADDR_SIZE 0x1000
#define UART6_PADDR_SIZE            0x1000
/* io space for cc */
#define DX_BASE_CC                           0xFDF0F000
#define DX_BASE_CC_SIZE                      0x100000
#define TEEOS_MEM_SIZE                       0x1800000
/* ddr space for cc */
#define SHMEM_SIZE                           0x2000
#define SHMEM_OFFSET                         (TEEOS_MEM_SIZE - SHMEM_SIZE)
/* io space for cc atlanta */
#define DX_BASE_ATLANTA                      0xEA980000
#define DX_BASE_ATL_SIZE                     0x100000
#define GIC_V2_DIST_ADDR                     0xE82B1000
#define GIC_V2_CONTR_ADDR                    0xE82B2000
#define GIC3_SECTIONS                        0
#define SPI_NUM                              376
#define PROTECTED_REGION_START               0x16B00000
#define PROTECTED_REGION_END                 0x16C01000

#define OFFSET_PADDR_TO_VADDR       0
/* io space for drv_timer */
#define TIMER1_BASE                 0xFFF15000
#define TIMER1_BASE_SIZE            0x1000
#define TIMER6_BASE                 0xFFF1A000
#define TIMER6_BASE_SIZE            0x1000
#define TIMER7_BASE                 0xFFF1B000
#define TIMER7_BASE_SIZE            0x1000
#ifndef RTC_BASE_ADDR
#define RTC_BASE_ADDR               0xFFF05000
#endif
#define RTC_BASE_ADDR_SIZE          0x1000
#define REG_BASE_SCTRL_SIZE         0x1000
#define REG_BASE_PERI_CRG_SIZE      0x1000
#define REG_BASE_PCTRL_SIZE         0x1000

#define RTC0_PADDR                  0x09010000
#define RTC0_PADDR_SIZE             0x1000
#define RTC1_PADDR                  0x09020000
#define RTC1_PADDR_SIZE             0x1000

#define GIC2_DIST_PADDR             0xE82B1000
#define GIC2_CONTR_PADDR            0xE82B2000

/* io space for tui */
#define SOC_ACPU_DMSS_BASE_ADDR_SIZE     0x8000
#define SOC_ACPU_PERI_CRG_BASE_ADDR_SIZE 0x1000

#define SOC_ACPU_DMSS_TZMP2_BASE_ADDR_SIZE 0x2000

#define PMC_BASE                    0xFFF31000
#define PMC_BASE_SIZE               0x1000

#define DSS_BASE                    0xE8600000
#define DSS_BASE_SIZE               0xC0000

#define PCTRL_BASE                  REG_BASE_PCTRL
#define PCTRL_BASE_SIZE             REG_BASE_PCTRL_SIZE
#define MMBUF_CFG_BASE              0xFFF02000
#define MMBUF_CFG_BASE_SIZE         0x1000
#define NOC_DSS_BASE                0xE86C0000
#define NOC_DSS_BASE_SIZE           0x1000

/* GPIO28,GPIO1_SE,AO_IOC */
#define TZPC                        0xE8A21000
#define TZPC_SIZE                   0x1000

/* MODEM */
#define HI_IPCM_REGBASE_ADDR        0xFF010000
#define HI_IPCM_REGBASE_ADDR_SIZE   0x1000

/* ISP */
#define CRG_BASE                    0xFFF35000
#define SOC_ACPU_ISP_CORE_CFG_BASE_ADDR_SIZE 0x200000
#define CRG_BASE_SIZE               0x1000

/* MEDIA */
#define MEDIA_CRG_BASE_ADDR         0xE87FF000
#define MEDIA_CRG_BASE_ADDR_SIZE    0x1000

/* HIFI */
#define HIFI_CFG_BASE_ADDR          0xE804E000
#define HIFI_CFG_BASE_ADDR_SIZE     0x1000

/* SECBOOT */
#define SECBOOT_XX                  0xFDF0F000
#define SECBOOT_XX_SIZE             0x1000
#define HI_SYSCTRL_BASE_ADDR        0xE0200000
#define HI_SYSCTRL_BASE_ADDR_SIZE   0x1000
#define SOC_ACPU_SCTRL_BASE_ADDR_SIZE 0x1000
#define HI_WDT_BASE_ADDR_VIRT       0xE0201000
#define HI_WDT_BASE_ADDR_VIRT_SIZE  0x1000

/* GPIO */
#define SOC_ACPU_GPIO0_BASE_ADDR_SIZE 0x1000
#define SOC_ACPU_GPIO6_BASE_ADDR_SIZE 0x1000
#define SOC_ACPU_GPIO25_BASE_ADDR_SIZE 0x1000
#define SOC_ACPU_GPIO4_BASE_ADDR_SIZE 0x1000
#define GPIO_SPI                    0xFFF10000
#define GPIO_SPI_SIZE               0x20000

/* Fingerprint */
#define RESET_PIN_GPIO_ADDR         0xFFF0F000
#define RESET_PIN_GPIO_ADDR_SIZE    0x1000

/* coresight etf2: for etf0,1 */
#define SOC_ACPU_CSSYS_APB_BASE_ADDR_SIZE 0x100000
/* Mate10 Pro THP */
#define SOC_ACPU_I2C7_BASE_ADDR_SIZE 0x1000

/* IOMCU */
#define SOC_ACPU_IOMCU_SPI2_BASE_ADDR_SIZE   0x1000
#define SOC_ACPU_IOMCU_CONFIG_BASE_ADDR_SIZE 0x1000
#define SOC_ACPU_IOMCU_DMAC_BASE_ADDR_SIZE   0x1000

/* Cambricon */
#define CAMBRICON_X1                 0xFF400000
#define CAMBRICON_X1_SIZE            0x100000
#define CAMBRICON_X2                 0xFF500000
#define CAMBRICON_X2_SIZE            0x100000

/* io space for cc atlanta */
#define DX_BASE_ATLANTA              0xEA980000
#define DX_BASE_ATL_SIZE             0x100000

/* io space for hisee */
#define HISEE_MBOX_BASE_ADDR         0xF0E20000
#define HISEE_MBOX_BASE_ADDR_SIZE    0x4000
#define HISEE_IPC_BASE_ADDR          0xF0E30000
#define HISEE_IPC_BASE_ADDR_SIZE     0x1000

/* SENSORHUB_IPC_BASE_ADDR */
#define SENSORHUB_IPC_BASE_ADDR           0xFA898000
#define SENSORHUB_IPC_BASE_ADDR_SIZE      0x1000

#define SOC_ACPU_VDEC_BASE_ADDR_SIZE 0x100000
/* io space for npu */
#define SOC_ACPU_VENC_BASE_ADDR_SIZE 0x100000

#define SOC_ACPU_UFS_CFG_BASE_ADDR_SIZE 0x20000

/* 0xFF343000 */
#define HDCP13_ADDR 0xFF340000
/* 0x1000 */
#define HDCP13_ADDR_SIZE 0x4000
#define HDCP22_ADDR 0xFF351000
#define HDCP22_ADDR_SIZE 0x2000

#endif
