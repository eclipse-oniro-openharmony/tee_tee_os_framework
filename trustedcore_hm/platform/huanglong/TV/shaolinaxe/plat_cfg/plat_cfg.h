/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Create: 2020-03
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

#define FREE_RUNNING_TIMER_NUM 0

#define GIC3_SECTIONS               2
#define TEEOS_MEM_SIZE              0x3000000

#define OFFSET_PADDR_TO_VADDR       0

#define TIMER1_BASE      0x00853000
#define TIMER1_BASE_SIZE 0x1000
#define TIMER7_BASE      0x00853100
#define TIMER7_BASE_SIZE 0x1000

#ifndef RTC_BASE_ADDR
#define RTC_BASE_ADDR 0xFFF05000
#endif

#define SHMEM_SIZE                    0x1000
#define SHMEM_OFFSET                  (TEEOS_MEM_SIZE - SHMEM_SIZE)

/*
 *  peripheral phys addrs range
 */
#define SYS_IO_ADDR_START           (0x00000000 - OFFSET_PADDR_TO_VADDR)
#define SYS_IO_ADDR_END             (0x0FFFFFFF - OFFSET_PADDR_TO_VADDR)
#define SYS_IO_ADDR_SIZE            0x10000000  /* 256M */

/*
 *  SYS CTRL
 */
#define REG_BASE_SYS_CTRL_PADDR     0x00840000
#define REG_BASE_SYS_CTRL           (0x00840000 - OFFSET_PADDR_TO_VADDR)
#define REG_SIZE_SYS_CTRL           0x2000

/*
 *  UART
 */
#define REG_BASE_UART               0x00870000
#define REG_SIZE_UART               0x1000

#define REG_BASE_UART0              0x00870000

#define UART_ADDR                 REG_BASE_UART0

/*
 * CONFIG_PL011_CLOCK is not used in itrustee now,
 * because itrustee not do UART init
 */
#ifdef CFG_HI_TEE_FPGA_SUPPORT
#define CONFIG_PL011_CLOCK          25000000
#else
#define CONFIG_PL011_CLOCK          75000000
#endif

#define REG_BASE_GIC                0x01A00000
#define REG_SIZE_GIC                0x200000

#define REG_BASE_GIC_CPU            0x0
#define REG_BASE_GIC_DIS            0x01A00000
#define REG_BASE_GIC_REDIS          0x01A40000

/*
 *  SEC TIMER
 */
#define REG_BASE_SEC_TIMER          0x00853000
#define REG_SIZE_SEC_TIMER          0x1000

#define REG_BASE_SEC_TIMER0         0x00853000  /* timer0_high 0x00853020 can not write */
#define REG_BASE_SEC_TIMER1         0x00853100  /* timer1 do not power off */

#define SEC_TIMER0_IRQ              (91 + 32)
#define SEC_TIMER1_IRQ              (92 + 32)

#define SEC_TIMER_CLK_RATE          (24 * 1000 * 1000)  /* 24MHZ */

/*
 *  RTC
 */
#define REG_BASE_RTC                0x016F0000
#define REG_SIZE_RTC                0x1000

#ifndef RTC_BASE_ADDR
#define RTC_BASE_ADDR               REG_BASE_RTC
#endif
#define RTC_BASE_ADDR_SIZE          REG_SIZE_RTC
/*
 *  DDRC(include TZASC)
 */
#define REG_BASE_DDRC_PADDR           0x00D00000
#define REG_BASE_DDRC                 (0x00D00000 - OFFSET_PADDR_TO_VADDR)
#define REG_SIZE_DDRC                 0x20000

#define REG_BASE_TZASC                (0x00D01000 - OFFSET_PADDR_TO_VADDR)

/*
 *  TEE_CTRL/TZPC
 */
#define REG_BASE_TEE_CTRL_PADDR       0x00B60000
#define REG_BASE_TEE_CTRL             (0x00B60000 - OFFSET_PADDR_TO_VADDR)
#define REG_SIZE_TEE_CTRL             0x1000

/*
 *  PASTC
 */
#define PASTC_BSE_REG_PADDR           0x00D40000
#define PASTC_BSE_REG                 (0x00D40000 - OFFSET_PADDR_TO_VADDR)
#define PASTC_BSE_SIZE                0x10000

/*
 *  RNG
 */
#define REG_BASE_RNG_PADDR            0x00B0C000
#define REG_BASE_RNG                  (0x00B0C000 - OFFSET_PADDR_TO_VADDR)
#define REG_SIZE_RNG                  0x1000

/*
 *  SPACC
 */
#define REG_BASE_SPACC_PADDR          0x00BC0000
#define REG_BASE_SPACC                (0x00BC0000 - OFFSET_PADDR_TO_VADDR)
#define REG_SIZE_SPACC                0x10000

/*
 *  KLAD/KEYSLOT
 */
#define REG_BASE_KLAD_PADDR           0x00B0A000
#define REG_BASE_KLAD                 (0x00B0A000 - OFFSET_PADDR_TO_VADDR)
#define REG_SIZE_KLAD                 0x1000

/*
 *  RKP
 */
#define REG_BASE_RKP_PADDR            0x00B05000
#define REG_BASE_RKP                  (0x00B05000 - OFFSET_PADDR_TO_VADDR)
#define REG_SIZE_RKP                  0x1000

/*
 *  OTP
 */
#define REG_BASE_OTP_PADDR            0x00B04000
#define REG_BASE_OTP                  (0x00B04000 - OFFSET_PADDR_TO_VADDR)
#define REG_SIZE_OTP                  0x1000
#define REG_BASE_OTP_SHADOW_PADDR     0x00B00000
#define REG_BASE_OTP_SHADOW           (0x00B00000 - OFFSET_PADDR_TO_VADDR)
#define REG_SIZE_OTP_SHADOW           0x1000

/*
 *  CERT
 */
#define REG_BASE_CERT_PADDR           0x00B09000
#define REG_BASE_CERT                 (0x00B09000 - OFFSET_PADDR_TO_VADDR)
#define REG_SIZE_CERT                 0x1000

/*
 *  PKE
 */
#define REG_BASE_PKE_PADDR             0x00B90000
#define REG_BASE_PKE                   (0x00B90000 - OFFSET_PADDR_TO_VADDR)
#define REG_SIZE_PKE                   0x2000

/*
 *  PASTC
 */
#define REG_BASE_PASTC                 0x00D40000
#define REG_SIZE_PASTC                 0x10000

/*
 *  system reset register
 */
#define REG_BASE_SYSRES_PADDR          0x00A13000
#define REG_BASE_SYSRES                (0x00A13000 - OFFSET_PADDR_TO_VADDR)
#define REG_SIZE_SYSRES                0x1000

/*
 *  SPI number
 */
#define SPI_NUM_FOR_NOTIFY             (107 + 32)
/*
 *  vfmw mdc register
 */
#define REG_BASE_MDC0CFG                0x01292000
#define REG_SIZE_MDC0CFG                0x1000
#define REG_BASE_MDC0STA                0x0129C000
#define REG_SIZE_MDC0STA                0x1000

/*
 *  MAILBOX
 */
#define REG_BASE_MAILBOX_VMCU            0x0129b000
#define REG_SIZE_MAILBOX_VMCU            0x1000
#define REG_BASE_MAILBOX_HPP             0x00B61000
#define REG_SIZE_MAILBOX_HPP             0x1000

/*
 *  CRG
 */
#define REG_BASE_CRG                     0x00A00000
#define REG_SIZE_CRG                     0x1000

/*
 *  DMX
 */
#define REG_BASE_MDSC                    0x00BEC000
#define REG_SIZE_MDSC                    0x2000
#define REG_BASE_DMX                     0x00C00000
#define REG_SIZE_DMX                     0x2F000
#define REG_BASE_DMX_IOMMU_TAG           0x00C2F000
#define REG_SIZE_DMX_IOMMU_TAG           0x1000

/*
 *  TSCIPHER
 */
#define REG_BASE_TSCIPHER                0x00BE0000
#define REG_SIZE_TSCIPHER                0xA000
#define REG_BASE_TSCIPHER_IOMMU_TAG      0x00BEA000
#define REG_SIZE_TSCIPHER_IOMMU_TAG      0x1000

/*
 *  VMCU
 */
#define REG_BASE_VMCU_IOMMU_TAG          0x01291000
#define REG_SIZE_VMCU_IOMMU_TAG          0x1000

/*
 *  VDH
 */
#define REG_BASE_VDH_IOMMU_TAG           0x01217000
#define REG_SIZE_VDH_IOMMU_TAG           0x5000

/*
 *  VPSS
 */
#define REG_BASE_VPSS_MAC_MMU_CTRL       0x01300000  /* 0x01300108 */
#define REG_SIZE_VPSS_MAC_MMU_CTRL       0x1000
#define REG_BASE_VPSS_IOMMU_TAG          0x01302000
#define REG_SIZE_VPSS_IOMMU_TAG          0x1000

/*
 *  VDP
 */
#define REG_BASE_VDP0_IOMMU_TAG          0xf0e000
#define REG_SIZE_VDP0_IOMMU_TAG          0x1000
#define REG_BASE_VDP1_IOMMU_TAG          0xf3e000
#define REG_SIZE_VDP1_IOMMU_TAG          0x1000
#define REG_BASE_VDP2_IOMMU_TAG          0xf0b000
#define REG_SIZE_VDP2_IOMMU_TAG          0x1000
#define REG_BASE_VDP_VID0_BASE_TAG       0xf3a000
#define REG_SIZE_VDP_VID0_BASE_TAG       0x1000
#define REG_BASE_VDP_VID1_BASE_TAG       0xf0a000
#define REG_SIZE_VDP_VID1_BASE_TAG       0x1000

#define REG_BASE_GFX2D_IOMMU_TAG         0x01408000
#define REG_SIZE_GFX2D_IOMMU_TAG         0x8000
#define REG_BASE_JPEGD_IOMMU_TAG         0x151F000
#define REG_SIZE_JPEGD_IOMMU_TAG         0x1000
#define REG_BASE_JPEGE_IOMMU_TAG         0x154F000
#define REG_SIZE_JPEGE_IOMMU_TAG         0x1000

/*
 *  VENC
 */
#define REG_BASE_VEDU_IOMMU_TAG          0x0150f000
#define REG_SIZE_VEDU_IOMMU_TAG          0x1000

/*
 *  VICAP
 */
#define REG_BASE_VICAP_IOMMU_TAG         0x00FCf000
#define REG_SIZE_VICAP_IOMMU_TAG         0x1000

/*
 *  GPU
 */
#define REG_BASE_GPU 0x190F000
#define REG_SIZE_GPU 0x1000

/*
 *  HDMITX
 */
#define REG_BASE_HDMITX0_PWD_TAG         0x01040000
#define REG_BASE_HDMITX0_AON_TAG         0x008d0000
#define REG_BASE_HDMITX0_PHY_TAG         0x0103f000
#define REG_BASE_HDMITX1_PWD_TAG         0x01000000
#define REG_BASE_HDMITX1_AON_TAG         0x010f8000
#define REG_BASE_HDMITX1_PHY_TAG         0x0107f000

#define REG_SIZE_HDMITX0_PWD_TAG         0x20000
#define REG_SIZE_HDMITX0_AON_TAG         0x1000
#define REG_SIZE_HDMITX0_PHY_TAG         0x1000
#define REG_SIZE_HDMITX1_PWD_TAG         0x20000
#define REG_SIZE_HDMITX1_AON_TAG         0x1000
#define REG_SIZE_HDMITX1_PHY_TAG         0x1000
/*
 *  HDMIRX
 */
#define REG_BASE_HDMIRX_CTRL0            0x01100000
#define REG_BASE_HDMIRX_CTRL1            0x01140000
#define REG_SIZE_HDMIRX_CTRL0            0x40000
#define REG_SIZE_HDMIRX_CTRL1            0x40000

/*
 *  NPU
 */
#define REG_BASE_NPU                    0x4000000
#define REG_SIZE_NPU                    0X2000000   /* 32M */
#define REG_BASE_GPIO_21                0x0A65000
#define REG_SIZE_GPIO_21                0X1000
#define REG_BASE_SYS_PERI               0xa10000
#define REG_SIZE_SYS_PERI               0X1000
#define REG_BASE_SYS_PMC                0xa15000
#define REG_SIZE_SYS_PMC                0X1000

#define GIC_DIST_PAGENUM            16
#define GIC_REDIST_PAGENUM          256
#define GIC_REDIST_NUM              1
#define GIC_REDIST_MEMSIZE          0x20000

#endif
