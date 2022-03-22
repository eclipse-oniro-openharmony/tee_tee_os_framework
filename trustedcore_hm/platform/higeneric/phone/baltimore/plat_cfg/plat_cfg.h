/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2020-03
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

#define UART_ADDR                     0xFFF02000

/* io space for cc */
#define DX_BASE_CC                    0xF8080000
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
#define PROTECTED_REGION_START1       0x13000000
#define PROTECTED_REGION_END1         0x13101000
#define PROTECTED_REGION_START2       0x13102000
#define PROTECTED_REGION_END2         0x135FF000

#define SOC_ACPU_IOMCU_DMAC_BASE_ADDR       0xFA877000
#define SOC_ACPU_IOMCU_DMAC_BASE_ADDR_SIZE  0x1000
#define FINGERPRINT_XX                      0xFA8AC000
#define FINGERPRINT_XX_SIZE                 0x1000
#define HIEPS_CDRM_BASE_ADDR                (0x2CD00000 + 0x80000)  /* size: 512k */
#define HIEPS_CDRM_ADDR_SIZE                (0x100000 - 0x80000)
#define SOC_ACPU_EPS_MMU_BASE_ADDR          0xE9580000  /* size: 12k */
#define SOC_ACPU_EPS_MMU_BASE_SIZE          0x3000
#define SOC_ACPU_EPS_PKE2_BASE_ADDR         0xE953A000  /* size: 16k */
#define SOC_ACPU_EPS_PKE2_BASE_SIZE         0x4000
#define SOC_ACPU_EPS_PKE_BASE_ADDR          0xE9512000
#define SOC_ACPU_EPS_PKE_BASE_SIZE          0x28000     /* size: 160k */
#define SOC_ACPU_EPS_SCE_BASE_ADDR          0xE9511000
#define SOC_ACPU_EPS_SCE_BASE_SIZE          0x1000      /* 4KB */
#define SOC_ACPU_EPS_KM_BASE_ADDR           0xE9510000
#define SOC_ACPU_EPS_KM_BASE_SIZE           0x1000      /* 4KB */
#define SOC_ACPU_EPS_SCE2_BASE_ADDR         0xE950F000
#define SOC_ACPU_EPS_SCE2_BASE_SIZE         0x1000      /* 4KB */
#define SOC_ACPU_EPS_TIMER_BASE_ADDR        0xE9504000
#define SOC_ACPU_EPS_TIMER_BASE_SIZE        0x1000      /* 4KB */
#define SOC_ACPU_EPS_TRNG_BASE_ADDR         0xE9502000
#define SOC_ACPU_EPS_TRNG_BASE_SIZE         0x2000      /* 8KB */
#define SOC_ACPU_EPS_ETZPC_BASE_ADDR        0xE9501000
#define SOC_ACPU_EPS_ETZPC_BASE_SIZE        0x1000      /* 4KB */
#define SOC_ACPU_EPS_CONFIG_BASE_ADDR       0xE9500000
#define SOC_ACPU_EPS_CONFIG_BASE_SIZE       0x1000      /* 4KB */
#define SOC_ACPU_MEDIA2_CRG_BASE_ADDR       0xE9400000
#define SOC_ACPU_MEDIA2_CRG_BASE_SIZE       0x1000      /* 4KB */
#define ACPU_SYS_CNT_BASE_ADDR              0xFA896000
#define ACPU_SYS_CNT_BASE_ADDR_SIZE         0x1000      /* size: 4KB */
#define SOC_ACPU_ACTRL_BASE_ADDR            0xFA894000
#define SOC_ACPU_ACTRL_BASE_ADDR_SIZE       0x1000      /* size: 4KB */
#define SOC_ACPU_PCTRL_BASE_ADDR_SIZE       0x1000      /* size: 4KB */

#define SOC_ACPU_IPC_NS_BASE_ADDR           0xFED01000
#define SOC_ACPU_IPC_NS_BASE_ADDR_SIZE      0x1000
#define SOC_ACPU_IPC_BASE_ADDR              0xFED00000
#define SOC_ACPU_IPC_BASE_ADDR_SIZE         0x1000
#define SOC_ACPU_AO_IPC_S_BASE_ADDR         0xFA898000
#define SOC_ACPU_AO_IPC_S_BASE_ADDR_SIZE    0x1000
#define SOC_ACPU_TIMER10_BASE_ADDR          0xFEC2D000
#define SOC_ACPU_TIMER10_BASE_ADDR_SIZE     0x1000

#define SOC_ACPU_SPI1_BASE_ADDR             0xFA048000
#define SOC_ACPU_SPI1_BASE_ADDR_SIZE        0x1000
#define SOC_ACPU_IOMCU_SPI2_BASE_ADDR       0xFA868000
#define SOC_ACPU_IOMCU_SPI2_BASE_ADDR_SIZE  0x1000
#define SOC_ACPU_SPI3_BASE_ADDR             0xFA89F000
#define SOC_ACPU_SPI3_BASE_ADDR_SIZE        0x1000
#define SOC_ACPU_SPI4_BASE_ADDR             0xFA049000
#define SOC_ACPU_SPI4_BASE_ADDR_SIZE 0x1000
#define SOC_ACPU_I3C4_BASE_ADDR             0xFA050000
#define SOC_ACPU_I3C4_BASE_ADDR_SIZE        0x1000
#define SOC_ACPU_AO_IOC_BASE_ADDR           0xFA89C000
#define SOC_ACPU_AO_IOC_BASE_ADDR_SIZE      0x1000
#define SOC_ACPU_IOC_BASE_ADDR              0xFED02000
#define SOC_ACPU_IOC_BASE_ADDR_SIZE         0x1000
#define SOC_ACPU_GPIO21_BASE_ADDR           0xFA8A9000
#define SOC_ACPU_GPIO21_BASE_ADDR_SIZE      0x1000
#define SOC_ACPU_GPIO1_BASE_ADDR           0xFEC13000
#define SOC_ACPU_GPIO1_BASE_ADDR_SIZE 0x1000
#define SOC_ACPU_GPIO5_BASE_ADDR            0xFEC17000
#define SOC_ACPU_GPIO5_BASE_ADDR_SIZE   0x1000
#define SOC_ACPU_GPIO0_SE_BASE_ADDR         0xFEC10000
#define SOC_ACPU_GPIO0_SE_BASE_ADDR_SIZE    0x1000
#define SOC_ACPU_GPIO1_SE_BASE_ADDR         0xFA8A1000
#define SOC_ACPU_GPIO1_SE_BASE_ADDR_SIZE    0x1000
#define AO_TZPC                             0xFA89E000
#define AO_TZPC_SIZE                        0x1000
#define SOC_ACPU_GPIO22_BASE_ADDR           0xFA8AA000
#define SOC_ACPU_GPIO22_BASE_ADDR_SIZE      0x1000
#define SOC_ACPU_GPIO28_BASE_ADDR           0xFA8B0000
#define SOC_ACPU_GPIO28_BASE_ADDR_SIZE      0x1000
#define SOC_ACPU_GPIO0_BASE_ADDR            0xFEC12000
#define SOC_ACPU_GPIO0_BASE_ADDR_SIZE       0x1000
#define SOC_ACPU_IOMCU_CONFIG_BASE_ADDR     0xFA87E000
#define SOC_ACPU_IOMCU_CONFIG_BASE_ADDR_SIZE 0x1000

#define SOC_ACPU_PCTRL_BASE_ADDR        0xFEC3E000
#define REG_BASE_PCTRL                  SOC_ACPU_PCTRL_BASE_ADDR
#define SOC_ACPU_UFS_CFG_BASE_ADDR      0xF8300000
#define SOC_ACPU_SCTRL_BASE_ADDR        0xFA89B000
#define REG_BASE_SCTRL                  SOC_ACPU_SCTRL_BASE_ADDR
#define SOC_ACPU_PERI_CRG_BASE_ADDR     0xFFF05000
#define REG_BASE_PERI_CRG               SOC_ACPU_PERI_CRG_BASE_ADDR
#define SOC_ACPU_DMSS_BASE_ADDR         0xFFE80000
#define SOC_ACPU_ISP_CORE_CFG_BASE_ADDR 0xE8200000
#define SOC_ACPU_CSI_ADAPTER_BASE_ADDR  0xE8080000

#define SMMUV3_MEDIA1_TCU_BASE_ADDR         0xE8003000
#define SMMUV3_MEDIA1_TCU_ADDR_SIZE         0x60000     /* size: 384KB */
#define SMMUV3_MEDIA2_TCU_BASE_ADDR         0xE9402000
#define SMMUV3_MEDIA2_TCU_ADDR_SIZE         0x60000     /* size: 384KB */
#define SMMUV3_NPU_TCU_BASE_ADDR            0xE5FC0000
#define SMMUV3_NPU_TCU_ADDR_SIZE            0x40000     /* size: 256KB */
#define SMMUV3_TS_TBU_BASE_ADDR             0xE4100000  /* SOC_ACPU_ts_tbu_BASE_ADDR */
#define SMMUV3_TS_TBU_BASE_SIZE             0x2000

#define SOC_ACPU_TSCPU_SYSCTRL_BASE_ADDR    0xE4002000
#define SOC_ACPU_TSCPU_SYSCTRL_BASE_SIZE    0x1000
#define SOC_ACPU_TS_SECURE0_BASE_ADDR       0xE4007000
#define SOC_ACPU_TS_SECURE0_BASE_SIZE       0x1000
#define SOC_ACPU_AIC0_SMMU_CFG_BASE_ADDR    0xE5F80000
#define SOC_ACPU_AIC0_SMMU_CFG_BASE_SIZE    0x2000
#define SOC_ACPU_AIC1_SMMU_CFG_BASE_ADDR    0xE5F60000
#define SOC_ACPU_AIC1_SMMU_CFG_BASE_SIZE    0x2000
#define SOC_ACPU_HWTS_ADDR                  0xE4300000
#define SOC_ACPU_HWTS_SIZE                  0x100000
#define SOC_ACPU_AIC0_BASE_ADDR             0xE5000000
#define SOC_ACPU_AIC0_BASE_SIZE             0x2000
#define SOC_ACPU_AIC1_BASE_ADDR             0xE5100000
#define SOC_ACPU_AIC1_BASE_SIZE             0x2000

#define OFFSET_PADDR_TO_VADDR   0
/* io space for drv_timer */
#define TIMER1_BASE                         0xFA881000
#define TIMER1_BASE_SIZE                    0x1000
#define TIMER6_BASE                         0xFA886000
#define TIMER6_BASE_SIZE                    0x1000
#define TIMER7_BASE                         0xFA887000
#define TIMER7_BASE_SIZE                    0x1000
#ifndef RTC_BASE_ADDR
#define RTC_BASE_ADDR                       0xFA88D000
#endif
#define RTC_BASE_ADDR_SIZE                  0x1000
#define REG_BASE_SCTRL_SIZE                 0x1000
#define REG_BASE_PERI_CRG_SIZE              0x1000
#define REG_BASE_PCTRL_SIZE                 0x1000

#define RTC0_PADDR                          0x09010000
#define RTC0_PADDR_SIZE                     0x1000
#define RTC1_PADDR                          0x09020000
#define RTC1_PADDR_SIZE                     0x1000

/* io space for tui */
#define SOC_ACPU_DMSS_BASE_ADDR_SIZE        0x30000

/* size: 0x1000 */
#define SOC_ACPU_DMC_0_BASE_ADDR            0xFFE04000
/* size: 0x1000 */
#define SOC_ACPU_DMC_1_BASE_ADDR            0xFFE24000
/* size: 0x1000 */
#define SOC_ACPU_DMC_2_BASE_ADDR            0xFFE44000
/* size: 0x1000 */
#define SOC_ACPU_DMC_3_BASE_ADDR            0xFFE64000
/* size: 0x1000 */
#define SOC_ACPU_DMC_BASE_ADDR_SIZE         0x1000
/* size: 0x1000 */
#define PMC_BASE                            0xFFF01000
#define PMC_BASE_SIZE                       0x1000

#define DSS_BASE                            0xE8900000
#define DSS_BASE_SIZE                       0x100000

#define PCTRL_BASE                          REG_BASE_PCTRL
#define PCTRL_BASE_SIZE                     REG_BASE_PCTRL_SIZE
#define MMBUF_CFG_BASE                      0xFFF02000
#define MMBUF_CFG_BASE_SIZE                 0x1000
#define NOC_DSS_BASE                        0xE86C0000
#define NOC_DSS_BASE_SIZE                   0x1000

#define GPIO_SPI                            0xFFF10000
#define GPIO_SPI_SIZE                       0x20000

/* size: 0x1000 */
#define TZPC                                0xFEC3C000
#define TZPC_SIZE                           0x1000
/* size: 0x1000 */
#define AO_TZPC                             0xFA89E000
#define AO_TZPC_SIZE                        0x1000

#define SOC_ACPU_GPIO0_BASE_ADDR_SIZE       0x1000
#define SOC_ACPU_GPIO6_BASE_ADDR            0xFEC18000
#define SOC_ACPU_GPIO6_BASE_ADDR_SIZE       0x1000
#define SOC_ACPU_GPIO25_BASE_ADDR_SIZE      0x1000
#define SOC_ACPU_GPIO4_BASE_ADDR_SIZE       0x1000

/* ISP */
#define CRG_BASE                             0xFFF05000
#define SOC_ACPU_CSI_ADAPTER_BASE_ADDR_SIZE  0x1000
#define SOC_ACPU_ISP_CORE_CFG_BASE_ADDR_SIZE 0x400000

#define CRG_BASE_SIZE                        0x1000

#define MEDIA_CRG_BASE_ADDR                  0xE8001000

#define MEDIA_CRG_BASE_ADDR_SIZE             0x1000

/* HIFI */
#define HIFI_CFG_BASE_ADDR                   0xFA54E000
#define HIFI_CFG_DMMU_BASE_ADDR              0xFA547000
#define HIFI_CFG_DMMU_BASE_SIZE              0x1000

#define HIFI_CFG_BASE_ADDR_SIZE              0x1000
/* MODEM */
#define HI_IPCM_REGBASE_ADDR                 0xFA080000
#define HI_IPCM_REGBASE_ADDR_SIZE            0x1000

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

/* Fingerprint */
#define RESET_PIN_GPIO_ADDR                  0xFFF0F000
#define RESET_PIN_GPIO_ADDR_SIZE             0x1000

/* coresight etf2: for etf0,1 */
#define SOC_ACPU_CSSYS_APB_BASE_ADDR_SIZE    0x100000
/* Mate10 Pro THP */
#define SOC_ACPU_I2C7_BASE_ADDR_SIZE 0x1000

/* IOMCU */
#define SOC_ACPU_IOMCU_SPI2_BASE_ADDR_SIZE   0x1000
#define SOC_ACPU_IOMCU_CONFIG_BASE_ADDR_SIZE 0x1000
#define SOC_ACPU_IOMCU_DMAC_BASE_ADDR_SIZE   0x1000

/* Cambricon */
#define CAMBRICON_X1                         0xFF400000
#define CAMBRICON_X1_SIZE                    0x100000
#define CAMBRICON_X2                         0xFF500000
#define CAMBRICON_X2_SIZE                    0x100000

/* io space for hisee */
#define HISEE_MBOX_BASE_ADDR                 0xFA220000
#define HISEE_MBOX_BASE_ADDR_SIZE            0x4000
#define HISEE_IPC_BASE_ADDR                  0xFA230000
#define HISEE_IPC_BASE_ADDR_SIZE             0x1000

/* SENSORHUB_IPC_BASE_ADDR */
#define SENSORHUB_IPC_BASE_ADDR              0xFA898000
#define SENSORHUB_IPC_BASE_ADDR_SIZE         0x1000

#define SOC_ACPU_VDEC_BASE_ADDR              0xE9200000
#define SOC_ACPU_VDEC_BASE_ADDR_SIZE         0x100000
/* io space for npu */
#define SOC_ACPU_VENC_BASE_ADDR_SIZE         0x100000

#define SOC_ACPU_UFS_CFG_BASE_ADDR_SIZE      0x20000

/* io space for HDCP */
#define HDCP_ADDR                            0xF8400000
#define HDCP_ADDR_SIZE                       0x1000
#define HDCP_DSS_ADDR                        0xF8481000
#define HDCP_DSS_ADDR_SIZE                   0x1000

/* ivp space for IMAGE */
#define SOC_IVP_IMAGE_BASE_ADDR_0            0xE9000000
#define SOC_IVP_IMAGE_BASE_ADDR_1            0xE9600000
#define SOC_IVP_IMAGE_BASE_ADDR_SIZE         0x200000 /* 2MB */


#endif
