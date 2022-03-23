/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: plat_cfg defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-03
 */
#ifndef PLAT_CFG_H
#define PLAT_CFG_H

/* UART */
#define UART_ADDR      0x11002000 /* UART0 */

#define OFFSET_PADDR_TO_VADDR  0

/* io space for drv_timer */
#define TIMER1_BASE            0x1000A000
#define TIMER1_BASE_SIZE       0x1000
#define RTC_BASE_ADDR          0x10026000  /* PMIF_SPI_BASE */
#define RTC_BASE_ADDR_SIZE     0x1000
#define IOCFG_UFSHCI_BASE           0x11270000
#define IOCFG_UFSHCI_SIZE           0x20000

/* fingerprint */
#define FINGERPRINT_XX              0xFDF06000 // size: 0x1000
#define FINGERPRINT_XX_SIZE         0x1000

/* io space for cc */
#define DX_BASE_CC                   0x10210000 // size: 0x100000
#define DX_BASE_CC_SIZE              0x100000
#define DX_CLOCK_BASE                0x10001000
#define DX_CLOCK_BASE_SIZE           0x1000
#define SPI0_BASE_ADDR               0x1100A000
#define SPI0_BASE_SIZE               0x1000
#define SPI1_BASE_ADDR               0x11010000
#define SPI1_BASE_SIZE               0x1000
#define SPI5_BASE_ADDR               0x11019000
#define SPI5_BASE_SIZE               0x1000
#define GPIO_BASE_ADDR               0x10005000
#define GPIO_BASE_SIAE               0x1000
#define IOCFG_RR_BASE_ADDR           0x10002000
#define IOCFG_RR_BASE_SIAE           0x1000

/* ddr space for cc */
#define TEEOS_MEM_SIZE              0
#define SHMEM_SIZE                  0x1000
#define SHMEM_OFFSET                0

#define PROTECTED_REGION_START1     0x4CE01000
#define PROTECTED_REGION_END1       0x4D000000

#define GIC_V3_DIST_ADDR            0x0C000000
#define GIC_V3_REDIST_ADDR          0x0C040000
#define GIC_DIST_PAGENUM            16
#define GIC_REDIST_PAGENUM          256
#define GIC_REDIST_NUM              1
#define GIC_REDIST_MEMSIZE          0x20000

/* mtk 4g_enable */
#define M_CHIP_4G_ENABLED_ADDR 0x10001f00 /* in the same page with DX_CLOCK_BASE */
#define M_CHIP_4G_ENABLED_MASK 0x2000

/* mtk hw attribute */
#define M_CHIP_HW_PHY_ADDR 0x8000000
#define M_CHIP_HW_PHY_SIZE 0x1000

#define MT6885_SPI_NUM        536

#define TRNG_BASE             0x1020F000
#define TRNG_BASE_SIZE        0x1000

/*
 * same with DX_CLOCK_BASE
 * mapped in SaSi_HalInit, which is called in SaSi_LibInit before SaSi_RND_Instantiation
 */
#define INFRACFG_AO_BASE      0x10001000
#define INFRACFG_AO_BASE_SIZE 0x1000
#define OFFSET_PADDR_TO_VADDR 0
/* m4u base addr */
#define M4U_BASE0_SEC_PA        0x1411e000
#define M4U_BASE0_SEC_SIZE          0x1000

/* smi larb base addr */
#define LARB0_BASE_PA   0x14118000
#define LARB1_BASE_PA   0x14119000
#define LARB2_BASE_PA   0x1F003000
#define LARB3_BASE_PA   0x1F004000
#define LARB4_BASE_PA   0x1602E000
#define LARB5_BASE_PA   0x1600D000
#define LARB6_BASE_PA   0x0
#define LARB7_BASE_PA   0x17010000
#define LARB8_BASE_PA   0x17810000
#define LARB9_BASE_PA   0x1502E000
#define LARB10_BASE_PA  0x0
#define LARB11_BASE_PA  0x1582E000
#define LARB12_BASE_PA  0x0
#define LARB13_BASE_PA  0x1A001000
#define LARB14_BASE_PA  0x1A002000
#define LARB15_BASE_PA  0x0
#define LARB16_BASE_PA  0x1A00F000
#define LARB17_BASE_PA  0x1A010000
#define LARB18_BASE_PA  0x1A011000
#define LARB19_BASE_PA  0x1B10F000
#define LARB20_BASE_PA  0x1B00F000
#define LARB_BASE_SIZE      0x1000

/* ddp reg pa base addr */
#define DDP_CONFIG      0x14116000
#define DDP_OVL0        0x14000000
#define DDP_OVL0_2L     0x14001000
#define DDP_OVL1_2L     0x14101000
#define DDP_RDMA0       0x14003000
#define DDP_RDMA1       0x14103000
#define DDP_WDMA0       0x14006000
#define DDP_COLOR0      0x14007000
#define DDP_CCORRO      0x14008000
#define DDP_AAL0        0x14009000
#define DDP_GAMMA0      0x1400a000
#define DDP_DITHER0     0x1400b000
#define DDP_DSI0        0x1400e000
#define DDP_DPI         0x14125000
#define DDP_MUTEX       0x14117000
#define DDP_SMI_LARB0   0x14118000
#define DDP_SMI_LARB1   0x14119000
#define DDP_SMI_COMMON  0x1411f000
#define DDP_RSZ0        0x1400c000
#define DDP_POSTMASK    0x1400d000
#define DDP_PWM0        0x1100e000
#define DDP_MIPITX0     0x11e50000
#define DDP_MIPITX1      0x11e60000
#define DDP_BASE_SIZE    0x1000

/* emi mpu base addr */
#define EMI_MPU_BASE    0x10226000
#define EMI_MPU_BASE_SIZE   0x1000

/* cmdq */
#define GCE_BASE_PA       0x10228000
#define GCE_BASE_PA_SIZE  0x1000
#endif
