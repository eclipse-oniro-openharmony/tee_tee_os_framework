#ifndef __PLATFORM_HI3650_H
#define __PLATFORM_HI3650_H

/*****************************************************************************
  2 宏定义
*****************************************************************************/

/* 寄存器说明：64K */
#define SOC_ACPU_BOOTROM_NAND_REMAP_BASE_ADDR         (0xFFFF0000)

/* 寄存器说明：32K */
#define SOC_ACPU_DMSS_BASE_ADDR                       (0xFFFC0000)

/* 寄存器说明：4K */
#define SOC_ACPU_DDRC_QOSB_0_BASE_ADDR                (0xFFFC8000)

/* 寄存器说明：4K */
#define SOC_ACPU_DDRC_DMC_0_0_BASE_ADDR               (0xFFFC9000)

/* 寄存器说明：4K */
#define SOC_ACPU_DDRC_DMC_0_1_BASE_ADDR               (0xFFFCA000)

/* 寄存器说明：4K */
#define SOC_ACPU_DDRC_QOSB_1_BASE_ADDR                (0xFFFCC000)

/* 寄存器说明：4K */
#define SOC_ACPU_DDRC_DMC_1_0_BASE_ADDR               (0xFFFCD000)

/* 寄存器说明：4K */
#define SOC_ACPU_DDRC_DMC_1_1_BASE_ADDR               (0xFFFCE000)

/* 寄存器说明：4K */
#define SOC_ACPU_PACK_A_BASE_ADDR                     (0xFFFD0000)

/* 寄存器说明：4K */
#define SOC_ACPU_DDRPHY_STATIC_A_BASE_ADDR            (0xFFFD1000)

/* 寄存器说明：4K */
#define SOC_ACPU_PACK_B_BASE_ADDR                     (0xFFFD2000)

/* 寄存器说明：4K */
#define SOC_ACPU_DDRPHY_STATIC_B_BASE_ADDR            (0xFFFD3000)

/* 寄存器说明：4K */
#define SOC_ACPU_PACK_C_BASE_ADDR                     (0xFFFD4000)

/* 寄存器说明：4K */
#define SOC_ACPU_DDRPHY_STATIC_C_BASE_ADDR            (0xFFFD5000)

/* 寄存器说明：4K */
#define SOC_ACPU_PACK_D_BASE_ADDR                     (0xFFFD6000)

/* 寄存器说明：4K */
#define SOC_ACPU_DDRPHY_STATIC_D_BASE_ADDR            (0xFFFD7000)

/* 寄存器说明：128K */
#define SOC_ACPU_NANDC_CFG_BASE_ADDR                  (0xFFFA0000)

/* 寄存器说明：128K */
#define SOC_ACPU_NANDC_BASE_ADDR                      (0xFFF80000)

/* 寄存器说明：64K */
#define SOC_ACPU_BOOTROM_BASE_ADDR                    (0xFFF60000)

/* 寄存器说明：64K */
#define SOC_ACPU_LPMCU_RAM_BASE_ADDR                  (0xFFF50000)

/* 寄存器说明：64K */
#define SOC_ACPU_LP_RAM_BASE_ADDR                     (0xFFF40000)

/* 寄存器说明：4K */
#define SOC_ACPU_LP_CONFIG_BASE_ADDR                  (0xFFF3F000)

/* 寄存器说明：4K */
#define SOC_ACPU_LP_TIMER_BASE_ADDR                   (0xFFF3E000)

/* 寄存器说明：4K */
#define SOC_ACPU_LP_Watchdog_BASE_ADDR                (0xFFF3D000)

/* 寄存器说明：4K */
#define SOC_ACPU_GNSPWM_BASE_ADDR                     (0xFFF37000)

/* 寄存器说明：4K */
#define SOC_ACPU_PMU_SSI1_BASE_ADDR                   (0xFFF36000)

/* 寄存器说明：4K */
#define SOC_ACPU_PERI_CRG_BASE_ADDR                   (0xFFF35000)

/* 寄存器说明：4K */
#define SOC_ACPU_PMU_SSI0_BASE_ADDR                   (0xFFF34000)

/* 寄存器说明：4K */
#define SOC_ACPU_PMU_I2C_BASE_ADDR                    (0xFFF33000)

/* 寄存器说明：4K */
#define SOC_ACPU_UART6_BASE_ADDR                      (0xFFF32000)

/* 寄存器说明：4K */
#define SOC_ACPU_PMC_BASE_ADDR                        (0xFFF31000)

/* 寄存器说明：4K */
#define SOC_ACPU_TSENSORC_BASE_ADDR                   (0xFFF30000)

/* 寄存器说明：4k */
#define SOC_ACPU_TIMER0_BASE_ADDR                     (0xFFF14000)

/* 寄存器说明：4k */
#define SOC_ACPU_TIMER1_BASE_ADDR                     (0xFFF15000)

/* 寄存器说明：4k */
#define SOC_ACPU_TIMER2_BASE_ADDR                     (0xFFF16000)

/* 寄存器说明：4k */
#define SOC_ACPU_TIMER3_BASE_ADDR                     (0xFFF17000)

/* 寄存器说明：4k */
#define SOC_ACPU_TIMER4_BASE_ADDR                     (0xFFF18000)

/* 寄存器说明：4k */
#define SOC_ACPU_TIMER5_BASE_ADDR                     (0xFFF19000)

/* 寄存器说明：4k */
#define SOC_ACPU_TIMER6_BASE_ADDR                     (0xFFF1A000)

/* 寄存器说明：4k */
#define SOC_ACPU_TIMER7_BASE_ADDR                     (0xFFF1B000)

/* 寄存器说明：4k */
#define SOC_ACPU_TIMER8_BASE_ADDR                     (0xFFF1C000)

/* 寄存器说明：4K */
#define SOC_ACPU_AO_IOC_BASE_ADDR                     (0xFFF11000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO30_BASE_ADDR                     (0xFFF1f000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO29_BASE_ADDR                     (0xFFF1e000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO28_BASE_ADDR                     (0xFFF1d000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO27_BASE_ADDR                     (0xFFF10000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO26_BASE_ADDR                     (0xFFF0F000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO25_BASE_ADDR                     (0xFFF0E000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO24_BASE_ADDR                     (0xFFF0D000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO23_BASE_ADDR                     (0xFFF0C000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO22_BASE_ADDR                     (0xFFF0B000)

/* 寄存器说明：4K */
#define SOC_ACPU_SCTRL_BASE_ADDR                      (0xFFF0A000)

/* 寄存器说明：8K */
#define SOC_ACPU_SYS_CNT_BASE_ADDR                    (0xFFF08000)

/* 寄存器说明：4K */
#define SOC_ACPU_SCI1_BASE_ADDR                       (0xFFF07000)

/* 寄存器说明：4K */
#define SOC_ACPU_SCI0_BASE_ADDR                       (0xFFF06000)

/* 寄存器说明：4K */
#define SOC_ACPU_RTC1_BASE_ADDR                       (0xFFF05000)

/* 寄存器说明：4K */
#define SOC_ACPU_RTC0_BASE_ADDR                       (0xFFF04000)

/* 寄存器说明：4K */
#define SOC_ACPU_EFUSEC_BASE_ADDR                     (0xFFF03000)

/* 寄存器说明：4K */
#define SOC_ACPU_MMBUF_CFG_BASE_ADDR                  (0xFFF02000)

/* 寄存器说明：4K */
#define SOC_ACPU_MMBUF_ASC1_BASE_ADDR                 (0xFFF01000)

/* 寄存器说明：4K */
#define SOC_ACPU_MMBUF_ASC0_BASE_ADDR                 (0xFFF00000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_RTC_BASE_ADDR                  (0xFFD7F000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_CONFIG_BASE_ADDR               (0xFFD7E000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_TIMER_BASE_ADDR                (0xFFD7D000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_Watchdog_BASE_ADDR             (0xFFD7C000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_GPIO3_BASE_ADDR                (0xFFD7B000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_GPIO2_BASE_ADDR                (0xFFD7A000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_GPIO1_BASE_ADDR                (0xFFD79000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_GPIO0_BASE_ADDR                (0xFFD78000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_DMAC_BASE_ADDR                 (0xFFD77000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_UART7_BASE_ADDR                (0xFFD76000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_BLPWM_BASE_ADDR                (0xFFD75000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_UART3_BASE_ADDR                (0xFFD74000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_I2C2_BASE_ADDR                 (0xFFD73000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_I2C1_BASE_ADDR                 (0xFFD72000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_I2C0_BASE_ADDR                 (0xFFD71000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_SPI_BASE_ADDR                  (0xFFD70000)

/* 寄存器说明：4K */
#define SOC_ACPU_DTCM1Remap_BASE_ADDR                 (0xFFD6F000)

/* 寄存器说明：4K */
#define SOC_ACPU_DTCM0Remap_BASE_ADDR                 (0xFFD6E000)

/* 寄存器说明：8K */
#define SOC_ACPU_ITCMRemap_BASE_ADDR                  (0xFFD6C000)

/* 寄存器说明：4K */
#define SOC_ACPU_RemapCtrl_BASE_ADDR                  (0xFFD6B000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_I2C3_BASE_ADDR                 (0xFFD6A000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_UART8_BASE_ADDR                (0xFFD69000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOMCU_SPI2_BASE_ADDR                 (0xFFD68000)

/* 寄存器说明：4K */
#define SOC_ACPU_SDIO0_BASE_ADDR                      (0xFF3FF000)

/* 寄存器说明：4K */
#define SOC_ACPU_EMMC1_BASE_ADDR                      (0xFF3FE000)

/* 寄存器说明：64K */
#define SOC_ACPU_EMMC0_BASE_ADDR                      (0xFF390000)

/* 寄存器说明：4K */
#define SOC_ACPU_SD_BASE_ADDR                         (0xFF37F000)

/* 寄存器说明：4K */
#define SOC_ACPU_SDIO1_BASE_ADDR                      (0xFF37D000)

/* 寄存器说明：4K */
#define SOC_ACPU_USB3OTG_BC_BASE_ADDR                 (0xFF200000)

/* 寄存器说明：1M */
#define SOC_ACPU_USB3OTG_BASE_ADDR                    (0xFF100000)

/* 寄存器说明：4K */
#define SOC_ACPU_SOCP_BASE_ADDR                       (0xFF030000)

/* 寄存器说明：4K */
#define SOC_ACPU_PERF_STAT_BASE_ADDR                  (0xFF012000)

/* 寄存器说明：4K */
#define SOC_ACPU_SECENG_S_BASE_ADDR                   (0xFF011000)

/* 寄存器说明：4K */
#define SOC_ACPU_SECENG_P_BASE_ADDR                   (0xFF010000)

/* 寄存器说明：16M */
#define SOC_ACPU_CS_STM_BASE_ADDR                     (0xFE000000)

/* 寄存器说明：4K */
#define SOC_ACPU_PERI_DMAC_BASE_ADDR                  (0xFDF30000)

/* 寄存器说明：4K */
#define SOC_ACPU_BISR_BASE_ADDR                       (0xFDF22000)

/* 寄存器说明：4K */
#define SOC_ACPU_IPC_MDM_BASE_ADDR                    (0xFDF21000)

/* 寄存器说明：4K */
#define SOC_ACPU_I2C7_BASE_ADDR                       (0xFDF0B000)

/* 寄存器说明：4K */
#define SOC_ACPU_I2C4_BASE_ADDR                       (0xFDF0D000)

/* 寄存器说明：4K */
#define SOC_ACPU_I2C3_BASE_ADDR                       (0xFDF0C000)

/* 寄存器说明：4K */
#define SOC_ACPU_SPI1_BASE_ADDR                       (0xFDF08000)

/* 寄存器说明：4K */
#define SOC_ACPU_UART5_BASE_ADDR                      (0xFDF05000)

/* 寄存器说明：4K */
#define SOC_ACPU_UART2_BASE_ADDR                      (0xFDF03000)

/* 寄存器说明：4K */
#define SOC_ACPU_UART0_BASE_ADDR                      (0xFDF02000)

/* 寄存器说明：4K */
#define SOC_ACPU_UART4_BASE_ADDR                      (0xFDF01000)

/* 寄存器说明：4K */
#define SOC_ACPU_UART1_BASE_ADDR                      (0xFDF00000)

/* 寄存器说明：12M */
#define SOC_ACPU_IOMCU_TCM_BASE_ADDR                  (0xF0000000)

/* 寄存器说明：32K */
#define SOC_ACPU_GIC_BASE_ADDR                        (0xE82B0000)

/* 寄存器说明：64K */
#define SOC_ACPU_CCI_CFG_BASE_ADDR                    (0xE8290000)

/* 寄存器说明：4K */
#define SOC_ACPU_A53_ROM_TABLE_BASE_ADDR              (0xEC800000)

/* 寄存器说明：4K */
#define SOC_ACPU_A53_FUNNEL_BASE_ADDR                 (0xEC801000)

/* 寄存器说明：4K */
#define SOC_ACPU_A53_ETF_BASE_ADDR                    (0xEC802000)

/* 寄存器说明：4K */
#define SOC_ACPU_A53_CTI_BASE_ADDR                    (0xEC803000)

/* 寄存器说明：4K */
#define SOC_ACPU_Maia_ROM_TABLE_BASE_ADDR             (0xED000000)

/* 寄存器说明：4K */
#define SOC_ACPU_Maia_FUNNEL_BASE_ADDR                (0xED001000)

/* 寄存器说明：4K */
#define SOC_ACPU_Maia_ETF_BASE_ADDR                   (0xED002000)

/* 寄存器说明：4K */
#define SOC_ACPU_Maia_CTI_BASE_ADDR                   (0xED003000)

/* 寄存器说明：24M */
#define SOC_ACPU_CSSYS_APB_BASE_ADDR                  (0xEC000000)

/* 寄存器说明：4K */
#define SOC_ACPU_CSSYS_ROM_TABLE_BASE_ADDR            (0xEC030000)

/* 寄存器说明：4K */
#define SOC_ACPU_CSSYS_FUNNEL_BASE_ADDR               (0xEC031000)

/* 寄存器说明：4K */
#define SOC_ACPU_CSSYS_TPIU_BASE_ADDR                 (0xEC032000)

/* 寄存器说明：4K */
#define SOC_ACPU_CSSYS_ETR_BASE_ADDR                  (0xEC033000)

/* 寄存器说明：4K */
#define SOC_ACPU_CSSYS_CTI_BASE_ADDR                  (0xEC034000)

/* 寄存器说明：4K */
#define SOC_ACPU_CSSYS_STM_BASE_ADDR                  (0xEC035000)

/* 寄存器说明：4K */
#define SOC_ACPU_CSSYS_ETF_BASE_ADDR                  (0xEC036000)

/* 寄存器说明：4K */
#define SOC_ACPU_CSSYS_Tsgen_BASE_ADDR                (0xEC037000)

/* 寄存器说明：4K */
#define SOC_ACPU_CSSYS_Tsgen_RO_BASE_ADDR             (0xEC038000)

/* 寄存器说明：400K */
#define SOC_ACPU_MMBUF_BASE_ADDR                      (0xEA800000)

/* 寄存器说明：2M */
#define SOC_ACPU_HKMEM_BASE_ADDR                      (0xEA000000)

/* 寄存器说明：64K */
#define SOC_ACPU_MMC0_NOC_Service_Target_BASE_ADDR    (0xE9890000)

/* 寄存器说明：64K */
#define SOC_ACPU_MMC1_NOC_Service_Target_BASE_ADDR    (0xE9880000)

/* 寄存器说明：64K */
#define SOC_ACPU_DEBUG_SEC_NOC_Service_Target_BASE_ADDR (0xE9870000)

/* 寄存器说明：64K */
#define SOC_ACPU_DMA_NOC_Service_Target_BASE_ADDR     (0xE9860000)

/* 寄存器说明：64K */
#define SOC_ACPU_IVP32_Sevice_Target_BASE_ADDR        (0xE9850000)

/* 寄存器说明：64K */
#define SOC_ACPU_SYS_BUS_Service_Target_BASE_ADDR     (0xE9840000)

/* 寄存器说明：64K */
#define SOC_ACPU_ASP_Service_Target_BASE_ADDR         (0xE9830000)

/* 寄存器说明：64K */
#define SOC_ACPU_Modem_Service_Target_BASE_ADDR       (0xE9820000)

/* 寄存器说明：64K */
#define SOC_ACPU_CFGBUS_Service_Target_BASE_ADDR      (0xE9800000)

/* 寄存器说明：128K */
#define SOC_ACPU_IVP32_SMMU_BASE_ADDR                 (0xE8DC0000)

/* 寄存器说明：4K */
#define SOC_ACPU_IVP32_TIMER1_BASE_ADDR               (0xE8D83000)

/* 寄存器说明：4K */
#define SOC_ACPU_IVP32_TIMER0_BASE_ADDR               (0xE8D82000)

/* 寄存器说明：4K */
#define SOC_ACPU_IVP32_Watchdog_BASE_ADDR             (0xE8D81000)

/* 寄存器说明：4K */
#define SOC_ACPU_IVP32_CFG_BASE_ADDR                  (0xE8D80000)

/* 寄存器说明：64K */
#define SOC_ACPU_IVP32_IRAM_BASE_ADDR                 (0xE8D00000)

/* 寄存器说明：64K */
#define SOC_ACPU_IVP32_DRAM1_BASE_ADDR                (0xE8C80000)

/* 寄存器说明：64K */
#define SOC_ACPU_IVP32_DRAM0_BASE_ADDR                (0xE8C00000)

/* 寄存器说明：4K */
#define SOC_ACPU_TZPC_BASE_ADDR                       (0xE8A21000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO0_BASE_ADDR                      (0xE8A0B000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO1_BASE_ADDR                      (0xE8A0C000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO2_BASE_ADDR                      (0xE8A0D000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO3_BASE_ADDR                      (0xE8A0E000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO4_BASE_ADDR                      (0xE8A0F000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO5_BASE_ADDR                      (0xE8A10000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO6_BASE_ADDR                      (0xE8A11000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO7_BASE_ADDR                      (0xE8A12000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO8_BASE_ADDR                      (0xE8A13000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO9_BASE_ADDR                      (0xE8A14000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO10_BASE_ADDR                     (0xE8A15000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO11_BASE_ADDR                     (0xE8A16000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO12_BASE_ADDR                     (0xE8A17000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO13_BASE_ADDR                     (0xE8A18000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO14_BASE_ADDR                     (0xE8A19000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO15_BASE_ADDR                     (0xE8A1A000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO16_BASE_ADDR                     (0xE8A1B000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO17_BASE_ADDR                     (0xE8A1C000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO18_BASE_ADDR                     (0xE8A1D000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO19_BASE_ADDR                     (0xE8A1E000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO20_BASE_ADDR                     (0xE8A1F000)

/* 寄存器说明：4K */
#define SOC_ACPU_GPIO21_BASE_ADDR                     (0xE8A20000)

/* 寄存器说明：4K */
#define SOC_ACPU_PCTRL_BASE_ADDR                      (0xE8A09000)

/* 寄存器说明：4K */
#define SOC_ACPU_Watchdog1_BASE_ADDR                  (0xE8A07000)

/* 寄存器说明：4K */
#define SOC_ACPU_Watchdog0_BASE_ADDR                  (0xE8A06000)

/* 寄存器说明：4K */
#define SOC_ACPU_PWM_BASE_ADDR                        (0xE8A04000)

/* 寄存器说明：4K */
#define SOC_ACPU_TIMER12_BASE_ADDR                    (0xE8A03000)

/* 寄存器说明：4K */
#define SOC_ACPU_TIMER11_BASE_ADDR                    (0xE8A02000)

/* 寄存器说明：4K */
#define SOC_ACPU_TIMER10_BASE_ADDR                    (0xE8A01000)

/* 寄存器说明：4K */
#define SOC_ACPU_TIMER9_BASE_ADDR                     (0xE8A00000)

/* 寄存器说明：16K */
#define SOC_ACPU_G3D_BASE_ADDR                        (0xE8970000)

/* 寄存器说明：4K */
#define SOC_ACPU_IOC_BASE_ADDR                        (0xE896C000)

/* 寄存器说明：4K */
#define SOC_ACPU_IPC_NS_BASE_ADDR                     (0xE896B000)

/* 寄存器说明：4K */
#define SOC_ACPU_IPC_BASE_ADDR                        (0xE896A000)

/* 寄存器说明：64K */
#define SOC_ACPU_NOC_VENC_Service_Target_BASE_ADDR    (0xE8940000)

/* 寄存器说明：64K */
#define SOC_ACPU_NOC_VDEC_Service_Target_BASE_ADDR    (0xE8930000)

/* 寄存器说明：64K */
#define SOC_ACPU_NOC_VCODECBUS_Service_Target_BASE_ADDR (0xE8920000)

/* 寄存器说明：64K */
#define SOC_ACPU_VENC_BASE_ADDR                       (0xE8900000)

/* 寄存器说明：1M */
#define SOC_ACPU_VDEC_BASE_ADDR                       (0xE8800000)

/* 寄存器说明：64K */
#define SOC_ACPU_NOC_ISP_Service_Target_BASE_ADDR     (0xE86D0000)

/* 寄存器说明：64K */
#define SOC_ACPU_NOC_DSS_Service_Target_BASE_ADDR     (0xE86C0000)

/* 寄存器说明：1M */
#define SOC_ACPU_ISP_CORE_CFG_BASE_ADDR               (0xE8400000)

/* 寄存器说明：128K */
#define SOC_ACPU_ISP_CORE_SRAM_BASE_ADDR              (0xE8500000)

/* 寄存器说明：4K */
#define SOC_ACPU_ISP_Watchdog_BASE_ADDR               (0xE8580000)

/* 寄存器说明：4K */
#define SOC_ACPU_ISP_TIMER_BASE_ADDR                  (0xE8581000)

/* 寄存器说明：4K */
#define SOC_ACPU_ISP_IPC_BASE_ADDR                    (0xE8582000)

/* 寄存器说明：4K */
#define SOC_ACPU_ISP_SUB_CTRL_BASE_ADDR               (0xE8583000)

/* 寄存器说明：4K */
#define SOC_ACPU_GLB0_BASE_ADDR                       (0xE8600000)

/* 寄存器说明：512B */
#define SOC_ACPU_DSI0_BASE_ADDR                       (0xE8601000)

/* 寄存器说明：512B */
#define SOC_ACPU_DSI1_BASE_ADDR                       (0xE8601400)

/* 寄存器说明：4608B */
#define SOC_ACPU_CMD_BASE_ADDR                        (0xE8602000)

/* 寄存器说明：4K */
#define SOC_ACPU_AIF0_BASE_ADDR                       (0xE8607000)

/* 寄存器说明：4K */
#define SOC_ACPU_AIF1_BASE_ADDR                       (0xE8609000)

/* 寄存器说明：4K */
#define SOC_ACPU_MIF_BASE_ADDR                        (0xE860A000)

/* 寄存器说明：2K */
#define SOC_ACPU_MCTL_SYS_BASE_ADDR                   (0xE8610000)

/* 寄存器说明：256B */
#define SOC_ACPU_MCTL_MUTEX0_BASE_ADDR                (0xE8610800)

/* 寄存器说明：256B */
#define SOC_ACPU_MCTL_MUTEX1_BASE_ADDR                (0xE8610900)

/* 寄存器说明：256B */
#define SOC_ACPU_MCTL_MUTEX2_BASE_ADDR                (0xE8610A00)

/* 寄存器说明：256B */
#define SOC_ACPU_MCTL_MUTEX3_BASE_ADDR                (0xE8610B00)

/* 寄存器说明：256B */
#define SOC_ACPU_MCTL_MUTEX4_BASE_ADDR                (0xE8610C00)

/* 寄存器说明：256B */
#define SOC_ACPU_MCTL_MUTEX5_BASE_ADDR                (0xE8610D00)

/* 寄存器说明：4K */
#define SOC_ACPU_DBUG_BASE_ADDR                       (0xE8611000)

/* 寄存器说明：32K */
#define SOC_ACPU_RCH_V0_BASE_ADDR                     (0xE8620000)

/* 寄存器说明：32K */
#define SOC_ACPU_RCH_V1_BASE_ADDR                     (0xE8628000)

/* 寄存器说明：32K */
#define SOC_ACPU_RCH_G0_BASE_ADDR                     (0xE8638000)

/* 寄存器说明：32K */
#define SOC_ACPU_RCH_G1_BASE_ADDR                     (0xE8640000)

/* 寄存器说明：4K */
#define SOC_ACPU_RCH_D0_BASE_ADDR                     (0xE8650000)

/* 寄存器说明：4K */
#define SOC_ACPU_RCH_D1_BASE_ADDR                     (0xE8651000)

/* 寄存器说明：4K */
#define SOC_ACPU_RCH_D2_BASE_ADDR                     (0xE8652000)

/* 寄存器说明：4K */
#define SOC_ACPU_RCH_D3_BASE_ADDR                     (0xE8653000)

/* 寄存器说明：4K */
#define SOC_ACPU_WCH0_BASE_ADDR                       (0xE865A000)

/* 寄存器说明：4K */
#define SOC_ACPU_WCH1_BASE_ADDR                       (0xE865C000)

/* 寄存器说明：1K */
#define SOC_ACPU_OV6_0_BASE_ADDR                      (0xE8660000)

/* 寄存器说明：1K */
#define SOC_ACPU_OV2_0_BASE_ADDR                      (0xE8660400)

/* 寄存器说明：1K */
#define SOC_ACPU_OV6_1_BASE_ADDR                      (0xE8660800)

/* 寄存器说明：1K */
#define SOC_ACPU_OV2_1_BASE_ADDR                      (0xE8660C00)

/* 寄存器说明：16K */
#define SOC_ACPU_SCF_BASE_ADDR                        (0xE8664000)

/* 寄存器说明：4K */
#define SOC_ACPU_DBUF0_BASE_ADDR                      (0xE866D000)

/* 寄存器说明：4K */
#define SOC_ACPU_DBUF1_BASE_ADDR                      (0xE866E000)

/* 寄存器说明：48K */
#define SOC_ACPU_DPP_BASE_ADDR                        (0xE8670000)

/* 寄存器说明：4K */
#define SOC_ACPU_SBL_BASE_ADDR                        (0xE867C000)

/* 寄存器说明：1K */
#define SOC_ACPU_INTF0_BASE_ADDR                      (0xE867D000)

/* 寄存器说明：1K */
#define SOC_ACPU_IFBC_BASE_ADDR                       (0xE867D400)

/* 寄存器说明：1K */
#define SOC_ACPU_DSC_BASE_ADDR                        (0xE867D800)

/* 寄存器说明：4K */
#define SOC_ACPU_INTF1_BASE_ADDR                      (0xE867E000)

/* 寄存器说明：4K */
#define SOC_ACPU_CODEC_SSI_BASE_ADDR                  (0xE82B9000)

/* 寄存器说明：4K */
#define SOC_ACPU_HKADC_SSI_BASE_ADDR                  (0xE1832000)

/* 寄存器说明：24K */
#define SOC_ACPU_DSP_ITCM_BASE_ADDR                   (0xE8070000)

/* 寄存器说明：96K */
#define SOC_ACPU_DSP_DTCM_BASE_ADDR                   (0xE8058000)

/* 寄存器说明：8K */
#define SOC_ACPU_SLIMBUS_BASE_ADDR                    (0xE8050000)

/* 寄存器说明：1K */
#define SOC_ACPU_SIO_MODEM_BASE_ADDR                  (0xE804FC00)

/* 寄存器说明：1K */
#define SOC_ACPU_SIO_BT_BASE_ADDR                     (0xE804F800)

/* 寄存器说明：1K */
#define SOC_ACPU_SIO_VOICE_BASE_ADDR                  (0xE804F400)

/* 寄存器说明：1K */
#define SOC_ACPU_SIO_AUDIO_BASE_ADDR                  (0xE804F000)

/* 寄存器说明：1K */
#define SOC_ACPU_ASP_HDMI_SPDIF_BASE_ADDR             (0xE804EC00)

/* 寄存器说明：1K */
#define SOC_ACPU_ASP_HDMI_SIO_BASE_ADDR               (0xE804E800)

/* 寄存器说明：1K */
#define SOC_ACPU_ASP_HDMI_ASP_BASE_ADDR               (0xE804E400)

/* 寄存器说明：1K */
#define SOC_ACPU_ASP_CFG_BASE_ADDR                    (0xE804E000)

/* 寄存器说明：4K */
#define SOC_ACPU_ASP_Watchdog_BASE_ADDR               (0xE804D000)

/* 寄存器说明：4K */
#define SOC_ACPU_ASP_IPC_BASE_ADDR                    (0xE804C000)

/* 寄存器说明：4K */
#define SOC_ACPU_ASP_DMAC_BASE_ADDR                   (0xE804B000)

/* 寄存器说明：4K */
#define SOC_ACPU_ASP_TIMER1_BASE_ADDR                 (0xE804A000)

/* 寄存器说明：4K */
#define SOC_ACPU_ASP_TIMER0_BASE_ADDR                 (0xE8049000)

/* 寄存器说明：4K */
#define SOC_ACPU_ASP_GPIO_BASE_ADDR                   (0xE8048000)

/* 寄存器说明：192K */
#define SOC_ACPU_SECRAM_BASE_ADDR                     (0xE8000000)

/* 寄存器说明：3584M */
#define SOC_ACPU_DRAM_BASE_ADDR                       (0x00000000)

/* 寄存器说明：512K */
#define SOC_ACPU_TL_BBE16_ITCM1_BASE_ADDR             (0xE2880000)

/* 寄存器说明：256K */
#define SOC_ACPU_TL_BBE16_ITCM0_BASE_ADDR             (0xE2840000)

/* 寄存器说明：512K */
#define SOC_ACPU_TL_BBE16_DTCM1_BASE_ADDR             (0xE2780000)

/* 寄存器说明：256K */
#define SOC_ACPU_TL_BBE16_DTCM0_BASE_ADDR             (0xE2740000)

/* 寄存器说明：96K */
#define SOC_ACPU_ON_CHIP_MEMORY_BASE_ADDR             (0xE0800000)

/* 寄存器说明：16K */
#define SOC_ACPU_AXI_MON_BASE_ADDR                    (0xE0476000)

/* 寄存器说明：4K */
#define SOC_ACPU_IPCM_BASE_ADDR                       (0xE0475000)

/* 寄存器说明：4K */
#define SOC_ACPU_VIC_BBE16_BASE_ADDR                  (0xE0474000)

/* 寄存器说明：4K */
#define SOC_ACPU_Modem_HS_UART_BASE_ADDR              (0xE0473000)

/* 寄存器说明：4K */
#define SOC_ACPU_Modem_IPF_BASE_ADDR                  (0xE0472000)

/* 寄存器说明：4K */
#define SOC_ACPU_UPACC_BASE_ADDR                      (0xE0471000)

/* 寄存器说明：4K */
#define SOC_ACPU_CIPHER_BASE_ADDR                     (0xE0470000)

/* 寄存器说明：64K */
#define SOC_ACPU_CICOM1_BASE_ADDR                     (0xE0450000)

/* 寄存器说明：64K */
#define SOC_ACPU_CICOM0_BASE_ADDR                     (0xE0440000)

/* 寄存器说明：256K */
#define SOC_ACPU_UICC_BASE_ADDR                       (0xE0400000)

/* 寄存器说明：4k */
#define SOC_ACPU_Modem_TIMER0_BASE_ADDR               (0xE0300000)

/* 寄存器说明：4k */
#define SOC_ACPU_Modem_TIMER1_BASE_ADDR               (0xE0301000)

/* 寄存器说明：4k */
#define SOC_ACPU_Modem_TIMER2_BASE_ADDR               (0xE0302000)

/* 寄存器说明：4k */
#define SOC_ACPU_Modem_TIMER3_BASE_ADDR               (0xE0303000)

/* 寄存器说明：4k */
#define SOC_ACPU_Modem_TIMER4_BASE_ADDR               (0xE0304000)

/* 寄存器说明：4k */
#define SOC_ACPU_Modem_TIMER5_BASE_ADDR               (0xE0305000)

/* 寄存器说明：4k */
#define SOC_ACPU_Modem_TIMER6_BASE_ADDR               (0xE0306000)

/* 寄存器说明：4k */
#define SOC_ACPU_Modem_TIMER7_BASE_ADDR               (0xE0307000)

/* 寄存器说明：4k */
#define SOC_ACPU_Modem_TIMER8_BASE_ADDR               (0xE0308000)

/* 寄存器说明：4K */
#define SOC_ACPU_Modem_TIMER9_BASE_ADDR               (0xE0309000)

/* 寄存器说明：4K */
#define SOC_ACPU_Modem_ASHB_Bridge_BASE_ADDR          (0xE0205000)

/* 寄存器说明：4K */
#define SOC_ACPU_Modem_EDMAC_BASE_ADDR                (0xE0204000)

/* 寄存器说明：4K */
#define SOC_ACPU_Modem_UART_BASE_ADDR                 (0xE0203000)

/* 寄存器说明：4K */
#define SOC_ACPU_Modem_WatchDog_BASE_ADDR             (0xE0201000)

/* 寄存器说明：4K */
#define SOC_ACPU_Modem_Sysctrl_BASE_ADDR              (0xE0200000)

/* 寄存器说明：1M */
#define SOC_ACPU_MCPU_Private_Space_BASE_ADDR         (0xE0100000)

/* 寄存器说明：1M */
#define SOC_ACPU_MCPU_L2Cache_BASE_ADDR               (0xE0000000)

/* 寄存器说明：1M */
#define SOC_ACPU_LTE_RFIN_BASE_ADDR                   (0xE1000000)

/* 寄存器说明：1M */
#define SOC_ACPU_LTE_FPU_BASE_ADDR                    (0xE1100000)

/* 寄存器说明：1M */
#define SOC_ACPU_BBP_DMA_BASE_ADDR                    (0xE1200000)

/* 寄存器说明：1M */
#define SOC_ACPU_DBG_BASE_ADDR                        (0xE1300000)

/* 寄存器说明：1M */
#define SOC_ACPU_LTE_PB_BASE_ADDR                     (0xE1400000)

/* 寄存器说明：1M */
#define SOC_ACPU_LTE_VDL_BASE_ADDR                    (0xE1500000)

/* 寄存器说明：1M */
#define SOC_ACPU_LTE_UL_BASE_ADDR                     (0xE1600000)

/* 寄存器说明：1M */
#define SOC_ACPU_LTE_INT_BASE_ADDR                    (0xE1700000)

/* 寄存器说明：512KB */
#define SOC_ACPU_GSM0_BASE_ADDR                       (0xE1800000)

/* 寄存器说明：512KB */
#define SOC_ACPU_GSM1_BASE_ADDR                       (0xE1880000)

/* 寄存器说明：1M */
#define SOC_ACPU_LTE_CQI_BASE_ADDR                    (0xE1A00000)

/* 寄存器说明：1M */
#define SOC_ACPU_LTE_PDU_BASE_ADDR                    (0xE1B00000)

/* 寄存器说明：1M */
#define SOC_ACPU_LTE_TDL_BASE_ADDR                    (0xE1C00000)

/* 寄存器说明：64K */
#define SOC_ACPU_TW_Share_BASE_ADDR                   (0xE1900000)

/* 寄存器说明：256K */
#define SOC_ACPU_WBBP_TOP1_BASE_ADDR                  (0xE1900000)

/* 寄存器说明：64K */
#define SOC_ACPU_XBBP_BASE_ADDR                       (0xE19E0000)

/* 寄存器说明：1M */
#define SOC_ACPU_TDS122_BASE_ADDR                     (0xE1D00000)

/* 寄存器说明：1M */
#define SOC_ACPU_TDS245_BASE_ADDR                     (0xE1E00000)

/* 寄存器说明：32K */
#define SOC_ACPU_CTU_BASE_ADDR                        (0xE1F80000)

/* 寄存器说明：8K */
#define SOC_ACPU_ET_BASE_ADDR                         (0xE1F88000)

/* 寄存器说明：2K */
#define SOC_ACPU_GU_BBP_MASTER_BASE_ADDR              (0xE1F8A800)

/* 寄存器说明：4K */
#define SOC_ACPU_IRM_PS_CFG_BASE_ADDR                 (0xE1F8B000)

/* 寄存器说明：8K */
#define SOC_ACPU_ABB_BASE_ADDR                        (0xE1F8C000)

/* 寄存器说明：8K */
#define SOC_ACPU_ABB_CFG_BASE_ADDR                    (0xE1F8E000)

/* 寄存器说明：2KB */
#define SOC_ACPU_LTE_ON_BASE_ADDR                     (0xE19A2000)

/* 寄存器说明：1KB */
#define SOC_ACPU_BBP_COMM_ON_BASE_ADDR                (0xE1832000)

/* 寄存器说明：1KB */
#define SOC_ACPU_GSM0_ON_BASE_ADDR                    (0xE1812800)

/* 寄存器说明：1KB */
#define SOC_ACPU_GSM1_ON_BASE_ADDR                    (0xE1892C00)

/* 寄存器说明：512B */
#define SOC_ACPU_AFC_CH0_BASE_ADDR                    (0xE19F2000)

/* 寄存器说明：512B */
#define SOC_ACPU_AFC_CH1_BASE_ADDR                    (0xE19F2000)

/* 寄存器说明：1KB */
#define SOC_ACPU_TDS_ON_BASE_ADDR                     (0xE19F3400)

/* 寄存器说明：512B */
#define SOC_ACPU_BBP_GLB_ON_BASE_ADDR                 (0xE19F2000)

/* 寄存器说明：512B */
#define SOC_ACPU_WCDMA_ON_BASE_ADDR                   (0xE19A2000)

/* 寄存器说明：512B */
#define SOC_ACPU_CDMA_ON_BASE_ADDR                    (0xE19F2000)

//LP_APB_PERI(128K)
#define REG_BASE_BOOTROM				SOC_ACPU_BOOTROM_NAND_REMAP_BASE_ADDR
#define REG_BASE_DDRC_CFG				SOC_ACPU_DMSS_BASE_ADDR
#define REG_BASE_DDRC_DMC_CFG		SOC_ACPU_DDRC_DMC_BASE_ADDR
#define REG_BASE_NANDC_CFG				SOC_ACPU_NANDC_CFG_BASE_ADDR
#define REG_BASE_NANDC					SOC_ACPU_NANDC_BASE_ADDR
#define REG_BASE_LPMCU_RAM				SOC_ACPU_LPMCU_RAM_BASE_ADDR
#define REG_BASE_LP_RAM					SOC_ACPU_LP_RAM_BASE_ADDR
#define REG_BASE_LP_CONFIG				SOC_ACPU_LP_CONFIG_BASE_ADDR
#define REG_BASE_LP_TIMER				SOC_ACPU_LP_TIMER_BASE_ADDR
#define REG_BASE_LP_WDG					SOC_ACPU_LP_Watchdog_BASE_ADDR
#define REG_BASE_GNSPWM					SOC_ACPU_GNSPWM_BASE_ADDR
#define REG_BASE_PMU_SSI1				SOC_ACPU_PMU_SSI1_BASE_ADDR
#define REG_BASE_PERICRG				SOC_ACPU_PERI_CRG_BASE_ADDR
#define REG_BASE_PERI_CRG				SOC_ACPU_PERI_CRG_BASE_ADDR
#define REG_BASE_PMU_SSI				SOC_ACPU_PMU_SSI0_BASE_ADDR
#define REG_BASE_PMU_I2C				SOC_ACPU_PMU_I2C_BASE_ADDR
#define REG_BASE_UART6					SOC_ACPU_UART6_BASE_ADDR
#define REG_BASE_PMC					SOC_ACPU_PMC_BASE_ADDR
#define REG_BASE_TSENSORC				SOC_ACPU_TSENSORC_BASE_ADDR
#define REG_BASE_TIMER0					SOC_ACPU_TIMER0_BASE_ADDR
#define REG_BASE_TIMER1					SOC_ACPU_TIMER1_BASE_ADDR
#define REG_BASE_TIMER2					SOC_ACPU_TIMER2_BASE_ADDR
#define REG_BASE_TIMER3					SOC_ACPU_TIMER3_BASE_ADDR
#define REG_BASE_TIMER4					SOC_ACPU_TIMER4_BASE_ADDR
#define REG_BASE_TIMER5					SOC_ACPU_TIMER5_BASE_ADDR
#define REG_BASE_TIMER6					SOC_ACPU_TIMER6_BASE_ADDR
#define REG_BASE_TIMER7					SOC_ACPU_TIMER7_BASE_ADDR
#define REG_BASE_TIMER8					SOC_ACPU_TIMER8_BASE_ADDR
#define REG_BASE_AO_IOC					SOC_ACPU_AO_IOC_BASE_ADDR
#define REG_BASE_GPIO30					SOC_ACPU_GPIO30_BASE_ADDR
#define REG_BASE_GPIO29					SOC_ACPU_GPIO29_BASE_ADDR
#define REG_BASE_GPIO28					SOC_ACPU_GPIO28_BASE_ADDR
#define REG_BASE_GPIO27					SOC_ACPU_GPIO27_BASE_ADDR
#define REG_BASE_GPIO26					SOC_ACPU_GPIO26_BASE_ADDR
#define REG_BASE_GPIO25					SOC_ACPU_GPIO25_BASE_ADDR
#define REG_BASE_GPIO24					SOC_ACPU_GPIO24_BASE_ADDR
#define REG_BASE_GPIO23					SOC_ACPU_GPIO23_BASE_ADDR
#define REG_BASE_GPIO22					SOC_ACPU_GPIO22_BASE_ADDR
#define REG_BASE_SYSCTRL				SOC_ACPU_SCTRL_BASE_ADDR
#define REG_BASE_SCTRL					SOC_ACPU_SCTRL_BASE_ADDR
#define REG_BASE_SYSCOUNT				SOC_ACPU_SYS_CNT_BASE_ADDR
#define REG_BASE_SCI1					SOC_ACPU_SCI1_BASE_ADDR
#define REG_BASE_SCI0					SOC_ACPU_SCI0_BASE_ADDR
#define REG_BASE_RTC1					SOC_ACPU_RTC1_BASE_ADDR
#define REG_BASE_RTC0					SOC_ACPU_RTC0_BASE_ADDR
#define REG_BASE_EFUSEC					SOC_ACPU_EFUSEC_BASE_ADDR
#define REG_BASE_MMBUF_CFG				SOC_ACPU_MMBUF_CFG_BASE_ADDR
#define REG_BASE_MMBUF_ASC1				SOC_ACPU_MMBUF_ASC1_BASE_ADDR
#define REG_BASE_MMBUF_ASC0				SOC_ACPU_MMBUF_ASC0_BASE_ADDR

//IOMCU_APB_PERIPH(512K)
#define REG_BASE_IOMCU_RTC				SOC_ACPU_IOMCU_RTC_BASE_ADDR
#define REG_BASE_IOMCU_CONFIG			SOC_ACPU_IOMCU_CONFIG_BASE_ADDR
#define REG_BASE_IOMCU_TIMER			SOC_ACPU_IOMCU_TIMER_BASE_ADDR
#define REG_BASE_IOMCU_WDG				SOC_ACPU_IOMCU_Watchdog_BASE_ADDR
#define REG_BASE_IOMCU_GPIO3			SOC_ACPU_IOMCU_GPIO3_BASE_ADDR
#define REG_BASE_IOMCU_GPIO2			SOC_ACPU_IOMCU_GPIO2_BASE_ADDR
#define REG_BASE_IOMCU_GPIO1			SOC_ACPU_IOMCU_GPIO1_BASE_ADDR
#define REG_BASE_IOMCU_GPIO0			SOC_ACPU_IOMCU_GPIO0_BASE_ADDR
#define REG_BASE_IOMCU_DMAC				SOC_ACPU_IOMCU_DMAC_BASE_ADDR
#define REG_BASE_IOMCU_UART7			SOC_ACPU_IOMCU_UART7_BASE_ADDR
#define REG_BASE_IOMCU_BLPWM			SOC_ACPU_IOMCU_BLPWM_BASE_ADDR
#define REG_BASE_I2C2					SOC_ACPU_IOMCU_I2C2_BASE_ADDR
#define REG_BASE_I2C1					SOC_ACPU_IOMCU_I2C1_BASE_ADDR
#define REG_BASE_I2C0					SOC_ACPU_IOMCU_I2C0_BASE_ADDR
#define REG_BASE_IOMCU_SPI				SOC_ACPU_IOMCU_SPI_BASE_ADDR
#define REG_BASE_DTCM1Remap				SOC_ACPU_DTCM1Remap_BASE_ADDR
#define REG_BASE_DTCM0Remap				SOC_ACPU_DTCM0Remap_BASE_ADDR
#define REG_BASE_ITCMRemap				SOC_ACPU_ITCMRemap_BASE_ADDR
#define REG_BASE_RemapCtrl				SOC_ACPU_RemapCtrl_BASE_ADDR
#define REG_BASE_I2C5					SOC_ACPU_IOMCU_I2C3_BASE_ADDR
#define REG_BASE_IOMCU_UART8			SOC_ACPU_IOMCU_UART8_BASE_ADDR
#define REG_BASE_IOMCU_SPI2				SOC_ACPU_IOMCU_SPI2_BASE_ADDR


#define REG_BASE_EMMC1					SOC_ACPU_EMMC1_BASE_ADDR
#define REG_BASE_EMMC0					SOC_ACPU_EMMC0_BASE_ADDR
#define REG_BASE_SD_V30					SOC_ACPU_SD_BASE_ADDR
#define REG_BASE_SDIO0					SOC_ACPU_SDIO0_BASE_ADDR
#define REG_BASE_SDIO1					SOC_ACPU_SDIO1_BASE_ADDR
#define REG_BASE_USB_OTG_BC				SOC_ACPU_USB3OTG_BC_BASE_ADDR
#define REG_BASE_USB_OTG				SOC_ACPU_USB3OTG_BASE_ADDR
#define REG_BASE_SOCP					SOC_ACPU_SOCP_BASE_ADDR
#define REG_BASE_SECENG_S				SOC_ACPU_SECENG_S_BASE_ADDR
#define REG_BASE_SECENG_P				SOC_ACPU_SECENG_P_BASE_ADDR
#define REG_BASE_CS_STM					SOC_ACPU_CS_STM_BASE_ADDR
#define REG_BASE_DMA0					SOC_ACPU_PERI_DMAC_BASE_ADDR
#define REG_BASE_IPC_MDM				SOC_ACPU_IPC_MDM_BASE_ADDR
#define REG_BASE_I2C4					SOC_ACPU_I2C4_BASE_ADDR
#define REG_BASE_I2C3					SOC_ACPU_I2C3_BASE_ADDR
#define REG_BASE_SPI1					SOC_ACPU_SPI1_BASE_ADDR
#define REG_BASE_UART5					SOC_ACPU_UART5_BASE_ADDR
#define REG_BASE_UART4					SOC_ACPU_UART4_BASE_ADDR
#define REG_BASE_UART3					(INVALID_VALUE)
#define REG_BASE_UART2					SOC_ACPU_UART2_BASE_ADDR
#define REG_BASE_UART1					SOC_ACPU_UART1_BASE_ADDR
#define REG_BASE_UART0					SOC_ACPU_UART0_BASE_ADDR
#define REG_BASE_UART					SOC_ACPU_UART6_BASE_ADDR
#define REG_BASE_IOMCU_TCM				SOC_ACPU_IOMCU_TCM_BASE_ADDR

#define REG_BASE_CSSYS_APB				SOC_ACPU_CSSYS_APB_BASE_ADDR
#define REG_BASE_MMBUF					SOC_ACPU_MMBUF_BASE_ADDR
#define REG_BASE_HKMEM					SOC_ACPU_HKMEM_BASE_ADDR
#define REG_BASE_MMC0_NOC_Service_Target		SOC_ACPU_MMC0_NOC_Service_Target_BASE_ADDR
#define REG_BASE_MMC1_NOC_Service_Target		SOC_ACPU_MMC1_NOC_Service_Target_BASE_ADDR
#define REG_BASE_DEBUG_SEC_NOC_Service_Target	SOC_ACPU_DEBUG_SEC_NOC_Service_Target_BASE_ADDR
#define REG_BASE_DMA_NOC_Service_Target			SOC_ACPU_DMA_NOC_Service_Target_BASE_ADDR
#define REG_BASE_IVP32_Sevice_Target			SOC_ACPU_IVP32_Sevice_Target_BASE_ADDR
#define REG_BASE_SYS_BUS_Service_Target			SOC_ACPU_SYS_BUS_Service_Target_BASE_ADDR
#define REG_BASE_ASP_Service_Target				SOC_ACPU_ASP_Service_Target_BASE_ADDR
#define REG_BASE_Modem_Service_Target			SOC_ACPU_Modem_Service_Target_BASE_ADDR
#define REG_BASE_CFGBUS_Service_Target			SOC_ACPU_CFGBUS_Service_Target_BASE_ADDR
#define REG_BASE_IVP32_SMMU				SOC_ACPU_IVP32_SMMU_BASE_ADDR
#define REG_BASE_IVP32_TIMER1			SOC_ACPU_IVP32_TIMER1_BASE_ADDR
#define REG_BASE_IVP32_TIMER0			SOC_ACPU_IVP32_TIMER0_BASE_ADDR
#define REG_BASE_IVP32_WDG				SOC_ACPU_IVP32_Watchdog_BASE_ADDR
#define REG_BASE_IVP32_CFG				SOC_ACPU_IVP32_CFG_BASE_ADDR
#define REG_BASE_IVP32_IRAM				SOC_ACPU_IVP32_IRAM_BASE_ADDR
#define REG_BASE_IVP32_DRAM1			SOC_ACPU_IVP32_DRAM1_BASE_ADDR
#define REG_BASE_IVP32_DRAM0			SOC_ACPU_IVP32_DRAM0_BASE_ADDR
#define REG_BASE_TZPC					SOC_ACPU_TZPC_BASE_ADDR

#define REG_BASE_GPIO0					SOC_ACPU_GPIO0_BASE_ADDR
#define REG_BASE_GPIO1					SOC_ACPU_GPIO1_BASE_ADDR
#define REG_BASE_GPIO2					SOC_ACPU_GPIO2_BASE_ADDR
#define REG_BASE_GPIO3					SOC_ACPU_GPIO3_BASE_ADDR
#define REG_BASE_GPIO4					SOC_ACPU_GPIO4_BASE_ADDR
#define REG_BASE_GPIO5					SOC_ACPU_GPIO5_BASE_ADDR
#define REG_BASE_GPIO6					SOC_ACPU_GPIO6_BASE_ADDR
#define REG_BASE_GPIO7					SOC_ACPU_GPIO7_BASE_ADDR
#define REG_BASE_GPIO8					SOC_ACPU_GPIO8_BASE_ADDR
#define REG_BASE_GPIO9					SOC_ACPU_GPIO9_BASE_ADDR
#define REG_BASE_GPIO10					SOC_ACPU_GPIO10_BASE_ADDR
#define REG_BASE_GPIO11					SOC_ACPU_GPIO11_BASE_ADDR
#define REG_BASE_GPIO12					SOC_ACPU_GPIO12_BASE_ADDR
#define REG_BASE_GPIO13					SOC_ACPU_GPIO13_BASE_ADDR
#define REG_BASE_GPIO14					SOC_ACPU_GPIO14_BASE_ADDR
#define REG_BASE_GPIO15					SOC_ACPU_GPIO15_BASE_ADDR
#define REG_BASE_GPIO16					SOC_ACPU_GPIO16_BASE_ADDR
#define REG_BASE_GPIO17					SOC_ACPU_GPIO17_BASE_ADDR
#define REG_BASE_GPIO18					SOC_ACPU_GPIO18_BASE_ADDR
#define REG_BASE_GPIO19					SOC_ACPU_GPIO19_BASE_ADDR
#define REG_BASE_GPIO20					SOC_ACPU_GPIO20_BASE_ADDR
#define REG_BASE_GPIO21					SOC_ACPU_GPIO21_BASE_ADDR
#define REG_BASE_PCTRL					SOC_ACPU_PCTRL_BASE_ADDR
#define REG_BASE_WD1					SOC_ACPU_Watchdog1_BASE_ADDR
#define REG_BASE_WD0					SOC_ACPU_Watchdog0_BASE_ADDR
#define REG_BASE_PWM					SOC_ACPU_PWM_BASE_ADDR
#define REG_BASE_TIMER12				SOC_ACPU_TIMER12_BASE_ADDR
#define REG_BASE_TIMER11				SOC_ACPU_TIMER11_BASE_ADDR
#define REG_BASE_TIMER10				SOC_ACPU_TIMER10_BASE_ADDR
#define REG_BASE_TIMER9					SOC_ACPU_TIMER9_BASE_ADDR
#define REG_BASE_IOC_SYS		    	SOC_ACPU_AO_IOC_BASE_ADDR
#define REG_BASE_IOC					SOC_ACPU_IOC_BASE_ADDR
#define REG_BASE_IPC_NS					SOC_ACPU_IPC_NS_BASE_ADDR
#define REG_BASE_IPC					SOC_ACPU_IPC_BASE_ADDR
#define REG_BASE_DSI1					SOC_ACPU_DSI1_BASE_ADDR
#define REG_BASE_DSI0					SOC_ACPU_DSI0_BASE_ADDR
#define REG_BASE_VENC_Service_Target			SOC_ACPU_NOC_VENC_Service_Target_BASE_ADDR
#define REG_BASE_VDEC_Service_Target			SOC_ACPU_NOC_VDEC_Service_Target_BASE_ADDR
#define REG_BASE_VCODEC_NOC_Service_Target		SOC_ACPU_NOC_VCODECBUS_Service_Target_BASE_ADDR
#define REG_BASE_G3D							SOC_ACPU_G3D_BASE_ADDR
#define REG_BASE_VENC							SOC_ACPU_VENC_BASE_ADDR
#define REG_BASE_VDEC							SOC_ACPU_VDEC_BASE_ADDR
#define REG_BASE_ISP_Service_Target				SOC_ACPU_NOC_ISP_Service_Target_BASE_ADDR
#define REG_BASE_VIVO_NOC_Service_Target		SOC_ACPU_NOC_DSS_Service_Target_BASE_ADDR
#define REG_BASE_ISP					SOC_ACPU_GLB0_BASE_ADDR
#define REG_BASE_CODEC_SSI				SOC_ACPU_CODEC_SSI_BASE_ADDR
#define HKADC_MAX_CHN					18
#define REG_BASE_EMMC_SDHCI				REG_BASE_EMMC0
#define REG_BASE_EMMC_DWMMC				REG_BASE_SDIO1
#define REG_BASE_HKADC_SSI				SOC_ACPU_HKADC_SSI_BASE_ADDR

#define REG_BASE_GIC					SOC_ACPU_GIC_BASE_ADDR
#define REG_BASE_CCI_CFG				SOC_ACPU_CCI_CFG_BASE_ADDR
#define REG_BASE_DSP_ITCM				SOC_ACPU_DSP_ITCM_BASE_ADDR
#define REG_BASE_DSP_DTCM				SOC_ACPU_DSP_DTCM_BASE_ADDR
#define REG_BASE_SLIMBUS				SOC_ACPU_SLIMBUS_BASE_ADDR
#define REG_BASE_SIO_MODEM				SOC_ACPU_SIO_MODEM_BASE_ADDR
#define REG_BASE_SIO_BT					SOC_ACPU_SIO_BT_BASE_ADDR
#define REG_BASE_SIO_VOICE				SOC_ACPU_SIO_VOICE_BASE_ADDR
#define REG_BASE_SIO_AUDIO				SOC_ACPU_SIO_AUDIO_BASE_ADDR
#define REG_BASE_ASP_HDMI_SPDIF			SOC_ACPU_ASP_HDMI_SPDIF_BASE_ADDR
#define REG_BASE_ASP_HDMI_SIO			SOC_ACPU_ASP_HDMI_SIO_BASE_ADDR
#define REG_BASE_ASP_HDMI_ASP			SOC_ACPU_ASP_HDMI_ASP_BASE_ADDR
#define REG_BASE_ASP_CFG				SOC_ACPU_ASP_CFG_BASE_ADDR
#define REG_BASE_ASP_WD					SOC_ACPU_ASP_Watchdog_BASE_ADDR
#define REG_BASE_ASP_IPC				SOC_ACPU_ASP_IPC_BASE_ADDR
#define REG_BASE_ASP_DMAC				SOC_ACPU_ASP_DMAC_BASE_ADDR
#define REG_BASE_ASP_TIMER1				SOC_ACPU_ASP_TIMER1_BASE_ADDR
#define REG_BASE_ASP_TIMER0				SOC_ACPU_ASP_TIMER0_BASE_ADDR
#define REG_BASE_ASP_GPIO				SOC_ACPU_ASP_GPIO_BASE_ADDR
#define REG_BASE_SECRAM					SOC_ACPU_SECRAM_BASE_ADDR
#define REG_BASE_DRAM					SOC_ACPU_DRAM_BASE_ADDR

#define REG_BASE_DSSCTRL				SOC_ACPU_GLB0_BASE_ADDR
#define REG_BASE_PMCCTRL				SOC_ACPU_PMC_BASE_ADDR
#define REG_BASE_ASPCTRL				SOC_ACPU_ASP_CFG_BASE_ADDR
#define REG_BASE_ASPDMACCTRL			SOC_ACPU_ASP_DMAC_BASE_ADDR

#define REG_BASE_PMUSSI					SOC_ACPU_PMU_SSI0_BASE_ADDR

#define REG_BASE_SPI1					SOC_ACPU_SPI1_BASE_ADDR

#define REG_BASE_SPI0					SOC_ACPU_IOMCU_SPI_BASE_ADDR

#define REG_BASE_SPI2					SOC_ACPU_IOMCU_SPI2_BASE_ADDR

#define REG_BASE_PMUSPI					SOC_ACPU_PMU_SSI0_BASE_ADDR

#define REG_BASE_MODEM					SOC_ACPU_MCPU_L2Cache_BASE_ADDR

#define REG_SYSCTRL_SCSYSSTAT		    (0x004)
#define REG_SYSCTRL_SCPERDIS		    (0x84)

#define M_DELAY_TIME(ms)				(1920 * ms)
#define U_DELAY_TIME(us)				(96 * us / 5 / 10)

/********************************************
 *  define gpio number in the way of group. *
 ********************************************/
#define GPIO_0_0    0
#define GPIO_0_1    1
#define GPIO_0_2    2
#define GPIO_0_3    3
#define GPIO_0_4    4
#define GPIO_0_5    5
#define GPIO_0_6    6
#define GPIO_0_7    7

#define GPIO_1_0    8
#define GPIO_1_1    9
#define GPIO_1_2    10
#define GPIO_1_3    11
#define GPIO_1_4    12
#define GPIO_1_5    13
#define GPIO_1_6    14
#define GPIO_1_7    15

#define GPIO_2_0    16
#define GPIO_2_1    17
#define GPIO_2_2    18
#define GPIO_2_3    19
#define GPIO_2_4    20
#define GPIO_2_5    21
#define GPIO_2_6    22
#define GPIO_2_7    23

#define GPIO_3_0    24
#define GPIO_3_1    25
#define GPIO_3_2    26
#define GPIO_3_3    27
#define GPIO_3_4    28
#define GPIO_3_5    29
#define GPIO_3_6    30
#define GPIO_3_7    31

#define GPIO_4_0    32
#define GPIO_4_1    33
#define GPIO_4_2    34
#define GPIO_4_3    35
#define GPIO_4_4    36
#define GPIO_4_5    37
#define GPIO_4_6    38
#define GPIO_4_7    39

#define GPIO_5_0    40
#define GPIO_5_1    41
#define GPIO_5_2    42
#define GPIO_5_3    43
#define GPIO_5_4    44
#define GPIO_5_5    45
#define GPIO_5_6    46
#define GPIO_5_7    47

#define GPIO_6_0    48
#define GPIO_6_1    49
#define GPIO_6_2    50
#define GPIO_6_3    51
#define GPIO_6_4    52
#define GPIO_6_5    53

#define GPIO_7_0    56
#define GPIO_7_1    57
#define GPIO_7_2    58
#define GPIO_7_3    59
#define GPIO_7_4    60
#define GPIO_7_5    61
#define GPIO_7_6    62
#define GPIO_7_7    63

#define GPIO_8_0    64
#define GPIO_8_1    65
#define GPIO_8_2    66
#define GPIO_8_3    67
#define GPIO_8_4    68
#define GPIO_8_5    69
#define GPIO_8_6    70
#define GPIO_8_7    71

#define GPIO_9_0    72
#define GPIO_9_1    73

#define GPIO_9_2    74
#define GPIO_9_3    75
#define GPIO_9_4    76

#define GPIO_9_5    77
#define GPIO_9_6    78
#define GPIO_9_7    79

#define GPIO_10_0   80
#define GPIO_10_1   81
#define GPIO_10_2   82
#define GPIO_10_3   83
#define GPIO_10_4   84
#define GPIO_10_5   85
#define GPIO_10_6   86
#define GPIO_10_7   87

#define GPIO_11_0   88
#define GPIO_11_1   89
#define GPIO_11_2   90
#define GPIO_11_3   91
#define GPIO_11_4   92
#define GPIO_11_5   93
#define GPIO_11_6   94
#define GPIO_11_7   95

#define GPIO_12_0   96
#define GPIO_12_1   97
#define GPIO_12_2   98
#define GPIO_12_3   99
#define GPIO_12_4   100
#define GPIO_12_5   101
#define GPIO_12_6   102
#define GPIO_12_7   103

#define GPIO_13_0   104
#define GPIO_13_1   105
#define GPIO_13_2   106
#define GPIO_13_3   107
#define GPIO_13_4   108
#define GPIO_13_5   109
#define GPIO_13_6   110
#define GPIO_13_7   111

#define GPIO_14_0   112
#define GPIO_14_1   113
#define GPIO_14_2   114
#define GPIO_14_3   115
#define GPIO_14_4   116
#define GPIO_14_5   117
#define GPIO_14_6   118
#define GPIO_14_7   119

#define GPIO_15_0   120
#define GPIO_15_1   121
#define GPIO_15_2   122
#define GPIO_15_3   123
#define GPIO_15_4   124
#define GPIO_15_5   125
#define GPIO_15_6   126
#define GPIO_15_7   127

#define GPIO_16_0   128
#define GPIO_16_1   129
#define GPIO_16_2   130
#define GPIO_16_3   131
#define GPIO_16_4   132
#define GPIO_16_5   133
#define GPIO_16_6   134
#define GPIO_16_7   135

#define GPIO_17_0   136
#define GPIO_17_1   137
#define GPIO_17_2   138
#define GPIO_17_3   139
#define GPIO_17_4   140
#define GPIO_17_5   141
#define GPIO_17_6   142
#define GPIO_17_7   143

#define GPIO_18_0   144
#define GPIO_18_1   145
#define GPIO_18_2   146
#define GPIO_18_3   147
#define GPIO_18_4   148
#define GPIO_18_5   149
#define GPIO_18_6   150
#define GPIO_18_7   151

#define GPIO_19_0   152
#define GPIO_19_1   153
#define GPIO_19_2   154
#define GPIO_19_3   155
#define GPIO_19_4   156
#define GPIO_19_5   157
#define GPIO_19_6   158
#define GPIO_19_7   159

#define GPIO_20_0   160
#define GPIO_20_1   161
#define GPIO_20_2   162
#define GPIO_20_3   163
#define GPIO_20_4   164
#define GPIO_20_5   165
#define GPIO_20_6   166
#define GPIO_20_7   167

#define GPIO_21_0   168
#define GPIO_21_1   169
#define GPIO_21_2   170
#define GPIO_21_3   171
#define GPIO_21_4   172
#define GPIO_21_5   173
#define GPIO_21_6   174
#define GPIO_21_7   175

#define GPIO_22_0   176
#define GPIO_22_1   177
#define GPIO_22_2   178
#define GPIO_22_3   179
#define GPIO_22_4   180
#define GPIO_22_5   181
#define GPIO_22_6   182
#define GPIO_22_7   183

#define GPIO_23_0   184
#define GPIO_23_1   185
#define GPIO_23_2   186
#define GPIO_23_3   187
#define GPIO_23_4   188
#define GPIO_23_5   189
#define GPIO_23_6   190
#define GPIO_23_7   191

#define GPIO_24_0   192
#define GPIO_24_1   193
#define GPIO_24_2   194
#define GPIO_24_3   195
#define GPIO_24_4   196
#define GPIO_24_5   197

#define GPIO_25_0   200
#define GPIO_25_1   201
#define GPIO_25_2   202
#define GPIO_25_3   203
#define GPIO_25_4   204
#define GPIO_25_5   205
#define GPIO_25_6   206
#define GPIO_25_7   207

#define GPIO_26_0   208
#define GPIO_26_1   209
#define GPIO_26_2   210
#define GPIO_26_3   211
#define GPIO_26_4   212
#define GPIO_26_5   213
#define GPIO_26_6   214
#define GPIO_26_7   215

#define GPIO_27_0   216
#define GPIO_27_1   217
#define GPIO_27_2   218

#define GPIO_6_6    144
#define GPIO_6_7    145
#define GPIO_24_6   224
#define GPIO_24_7   225
#define GPIO_27_3   232
#define GPIO_27_4   233
#define GPIO_27_5   234
#define GPIO_27_6   235

/********************************************
 *  define gpio number in the way of single.*
 ********************************************/

/*define GPIO 0 ~ GPIO 7*/
#define   GPIO_000     GPIO_0_0
#define   GPIO_001     GPIO_0_1
#define   GPIO_002     GPIO_0_2
#define   GPIO_003     GPIO_0_3
#define   GPIO_004     GPIO_0_4
#define   GPIO_005     GPIO_0_5
#define   GPIO_006     GPIO_0_6
#define   GPIO_007     GPIO_0_7

/*define GPIO 8 ~ GPIO 15*/
#define   GPIO_008     GPIO_1_0
#define   GPIO_009     GPIO_1_1
#define   GPIO_010     GPIO_1_2
#define   GPIO_011     GPIO_1_3
#define   GPIO_012     GPIO_1_4
#define   GPIO_013     GPIO_1_5
#define   GPIO_014     GPIO_1_6
#define   GPIO_015     GPIO_1_7

/*define GPIO 16 ~ GPIO 23*/
#define   GPIO_016     GPIO_2_0
#define   GPIO_017     GPIO_2_1
#define   GPIO_018     GPIO_2_2
#define   GPIO_019     GPIO_2_3
#define   GPIO_020     GPIO_2_4
#define   GPIO_021     GPIO_2_5
#define   GPIO_022     GPIO_2_6
#define   GPIO_023     GPIO_2_7

/*define GPIO 24 ~ GPIO 31*/
#define   GPIO_024     GPIO_3_0
#define   GPIO_025     GPIO_3_1
#define   GPIO_026     GPIO_3_2
#define   GPIO_027     GPIO_3_3
#define   GPIO_028     GPIO_3_4
#define   GPIO_029     GPIO_3_5
#define   GPIO_030     GPIO_3_6
#define   GPIO_031     GPIO_3_7

/*define GPIO 32 ~ GPIO 39*/
#define   GPIO_032     GPIO_4_0
#define   GPIO_033     GPIO_4_1
#define   GPIO_034     GPIO_4_2
#define   GPIO_035     GPIO_4_3
#define   GPIO_036     GPIO_4_4
#define   GPIO_037     GPIO_4_5
#define   GPIO_038     GPIO_4_6
#define   GPIO_039     GPIO_4_7

/*define GPIO 40 ~ GPIO 47*/
#define   GPIO_040     GPIO_5_0
#define   GPIO_041     GPIO_5_1
#define   GPIO_042     GPIO_5_2
#define   GPIO_043     GPIO_5_3
#define   GPIO_044     GPIO_5_4
#define   GPIO_045     GPIO_5_5
#define   GPIO_046     GPIO_5_6
#define   GPIO_047     GPIO_5_7

/*define GPIO 48 ~ GPIO 55*/
#define   GPIO_048     GPIO_6_0
#define   GPIO_049     GPIO_6_1
#define   GPIO_050     GPIO_6_2
#define   GPIO_051     GPIO_6_3
#define   GPIO_052     GPIO_6_4
#define   GPIO_053     GPIO_6_5
#define   GPIO_054     GPIO_6_6
#define   GPIO_055     GPIO_6_7

/*define GPIO 56 ~ GPIO 63*/
#define   GPIO_056     GPIO_7_0
#define   GPIO_057     GPIO_7_1
#define   GPIO_058     GPIO_7_2
#define   GPIO_059     GPIO_7_3
#define   GPIO_060     GPIO_7_4
#define   GPIO_061     GPIO_7_5
#define   GPIO_062     GPIO_7_6
#define   GPIO_063     GPIO_7_7

/*define GPIO 64 ~ GPIO 71*/
#define   GPIO_064     GPIO_8_0
#define   GPIO_065     GPIO_8_1
#define   GPIO_066     GPIO_8_2
#define   GPIO_067     GPIO_8_3
#define   GPIO_068     GPIO_8_4
#define   GPIO_069     GPIO_8_5
#define   GPIO_070     GPIO_8_6
#define   GPIO_071     GPIO_8_7

/*define GPIO 72 ~ GPIO 79*/
#define   GPIO_072     GPIO_9_0
#define   GPIO_073     GPIO_9_1

#define   GPIO_074     GPIO_9_2
#define   GPIO_075     GPIO_9_3
#define   GPIO_076     GPIO_9_4

#define   GPIO_077     GPIO_9_5
#define   GPIO_078     GPIO_9_6
#define   GPIO_079     GPIO_9_7

/*define GPIO 80 ~ GPIO 87*/
#define   GPIO_080     GPIO_10_0
#define   GPIO_081     GPIO_10_1
#define   GPIO_082     GPIO_10_2
#define   GPIO_083     GPIO_10_3
#define   GPIO_084     GPIO_10_4
#define   GPIO_085     GPIO_10_5
#define   GPIO_086     GPIO_10_6
#define   GPIO_087     GPIO_10_7

/*define GPIO 88 ~ GPIO 95*/
#define   GPIO_088     GPIO_11_0
#define   GPIO_089     GPIO_11_1
#define   GPIO_090     GPIO_11_2
#define   GPIO_091     GPIO_11_3
#define   GPIO_092     GPIO_11_4
#define   GPIO_093     GPIO_11_5
#define   GPIO_094     GPIO_11_6
#define   GPIO_095     GPIO_11_7

/*define GPIO 96 ~ GPIO 103*/
#define   GPIO_096     GPIO_12_0
#define   GPIO_097     GPIO_12_1
#define   GPIO_098     GPIO_12_2
#define   GPIO_099     GPIO_12_3
#define   GPIO_100     GPIO_12_4
#define   GPIO_101     GPIO_12_5
#define   GPIO_102     GPIO_12_6
#define   GPIO_103     GPIO_12_7

/*define GPIO 104 ~ GPIO 111*/
#define   GPIO_104     GPIO_13_0
#define   GPIO_105     GPIO_13_1
#define   GPIO_106     GPIO_13_2
#define   GPIO_107     GPIO_13_3
#define   GPIO_108     GPIO_13_4
#define   GPIO_109     GPIO_13_5
#define   GPIO_110     GPIO_13_6
#define   GPIO_111     GPIO_13_7

/*define GPIO 112 ~ GPIO 119*/
#define   GPIO_112     GPIO_14_0
#define   GPIO_113     GPIO_14_1
#define   GPIO_114     GPIO_14_2
#define   GPIO_115     GPIO_14_3
#define   GPIO_116     GPIO_14_4
#define   GPIO_117     GPIO_14_5
#define   GPIO_118     GPIO_14_6
#define   GPIO_119     GPIO_14_7

/*define GPIO 120 ~ GPIO 127*/
#define   GPIO_120     GPIO_15_0
#define   GPIO_121     GPIO_15_1
#define   GPIO_122     GPIO_15_2
#define   GPIO_123     GPIO_15_3
#define   GPIO_124     GPIO_15_4
#define   GPIO_125     GPIO_15_5
#define   GPIO_126     GPIO_15_6
#define   GPIO_127     GPIO_15_7

/*define GPIO 128 ~ GPIO 135*/
#define   GPIO_128     GPIO_16_0
#define   GPIO_129     GPIO_16_1
#define   GPIO_130     GPIO_16_2
#define   GPIO_131     GPIO_16_3
#define   GPIO_132     GPIO_16_4
#define   GPIO_133     GPIO_16_5
#define   GPIO_134     GPIO_16_6
#define   GPIO_135     GPIO_16_7

/*define GPIO 136 ~ GPIO 143*/
#define   GPIO_136     GPIO_17_0
#define   GPIO_137     GPIO_17_1
#define   GPIO_138     GPIO_17_2
#define   GPIO_139     GPIO_17_3
#define   GPIO_140     GPIO_17_4
#define   GPIO_141     GPIO_17_5
#define   GPIO_142     GPIO_17_6
#define   GPIO_143     GPIO_17_7

/*define GPIO 144 ~ GPIO 151*/
#define   GPIO_144     GPIO_18_0
#define   GPIO_145     GPIO_18_1
#define   GPIO_146     GPIO_18_2
#define   GPIO_147     GPIO_18_3
#define   GPIO_148     GPIO_18_4
#define   GPIO_149     GPIO_18_5
#define   GPIO_150     GPIO_18_6
#define   GPIO_151     GPIO_18_7

/*define GPIO 152 ~ GPIO 159*/
#define   GPIO_152     GPIO_19_0
#define   GPIO_153     GPIO_19_1
#define   GPIO_154     GPIO_19_2
#define   GPIO_155     GPIO_19_3
#define   GPIO_156     GPIO_19_4
#define   GPIO_157     GPIO_19_5
#define   GPIO_158     GPIO_19_6
#define   GPIO_159     GPIO_19_7

/*define GPIO 160 ~ GPIO 167*/
#define   GPIO_160     GPIO_20_0
#define   GPIO_161     GPIO_20_1
#define   GPIO_162     GPIO_20_2
#define   GPIO_163     GPIO_20_3
#define   GPIO_164     GPIO_20_4
#define   GPIO_165     GPIO_20_5
#define   GPIO_166     GPIO_20_6
#define   GPIO_167     GPIO_20_7

/*define GPIO 168 ~ GPIO 175*/
#define   GPIO_168     GPIO_21_0
#define   GPIO_169     GPIO_21_1
#define   GPIO_170     GPIO_21_2
#define   GPIO_171     GPIO_21_3
#define   GPIO_172     GPIO_21_4
#define   GPIO_173     GPIO_21_5
#define   GPIO_174     GPIO_21_6
#define   GPIO_175     GPIO_21_7


/*define GPIO 176 ~ GPIO 183*/
#define   GPIO_176     GPIO_22_0
#define   GPIO_177     GPIO_22_1
#define   GPIO_178     GPIO_22_2
#define   GPIO_179     GPIO_22_3
#define   GPIO_180     GPIO_22_4
#define   GPIO_181     GPIO_22_5
#define   GPIO_182     GPIO_22_6
#define   GPIO_183     GPIO_22_7

/*define GPIO 184 ~ GPIO 191*/
#define   GPIO_184     GPIO_23_0
#define   GPIO_185     GPIO_23_1
#define   GPIO_186     GPIO_23_2
#define   GPIO_187     GPIO_23_3
#define   GPIO_188     GPIO_23_4
#define   GPIO_189     GPIO_23_5
#define   GPIO_190     GPIO_23_6
#define   GPIO_191     GPIO_23_7

/*define GPIO 192 ~ GPIO 199*/
#define   GPIO_192     GPIO_24_0
#define   GPIO_193     GPIO_24_1
#define   GPIO_194     GPIO_24_2
#define   GPIO_195     GPIO_24_3
#define   GPIO_196     GPIO_24_4
#define   GPIO_197     GPIO_24_5
#define   GPIO_198     GPIO_24_6
#define   GPIO_199     GPIO_24_7

/*define GPIO 200 ~ GPIO 207*/
#define   GPIO_200     GPIO_25_0
#define   GPIO_201     GPIO_25_1
#define   GPIO_202     GPIO_25_2
#define   GPIO_203     GPIO_25_3
#define   GPIO_204     GPIO_25_4
#define   GPIO_205     GPIO_25_5
#define   GPIO_206     GPIO_25_6
#define   GPIO_207     GPIO_25_7

/*define GPIO 208 ~ GPIO 213*/
#define   GPIO_208     GPIO_26_0
#define   GPIO_209     GPIO_26_1
#define   GPIO_210     GPIO_26_2
#define   GPIO_211     GPIO_26_3
#define   GPIO_212     GPIO_26_4
#define   GPIO_213     GPIO_26_5
#define   GPIO_214     GPIO_26_6
#define   GPIO_215     GPIO_26_7

/*define GPIO 208 ~ GPIO 213*/
#define   GPIO_216     GPIO_27_0
#define   GPIO_217     GPIO_27_1
#define   GPIO_218     GPIO_27_2
#define   GPIO_219     GPIO_27_3
#define   GPIO_220     GPIO_27_4
#define   GPIO_221     GPIO_27_5
#define   GPIO_222     GPIO_27_6

#define             TEST_MODE            GPIO_001
#define              PMU0_SSI            GPIO_002
#define              PMU1_SSI            GPIO_003
#define        JTAG_TCK_SWCLK            GPIO_004
#define        JTAG_TMS_SWDIO            GPIO_005
#define           JTAG_TRST_N            GPIO_006
#define              JTAG_TDI            GPIO_007
#define              JTAG_TDO            GPIO_008
#define              I2C3_SCL            GPIO_009
#define              I2C3_SDA            GPIO_010
#define              SPI1_CLK            GPIO_011
#define               SPI1_DI            GPIO_012
#define               SPI1_DO            GPIO_013
#define             SPI1_CS_N            GPIO_014
#define               GPS_REF            GPIO_016
#define     ISP_GPIO00_FTRSTN            GPIO_017
#define     ISP_GPIO01_BKRSTN            GPIO_018
#define      ISP_GPIO02_MNTRB            GPIO_019
#define      ISP_GPIO06_FSYNC            GPIO_020
#define      ISP_GPIO10_SBPWM            GPIO_021
#define              ISP_CLK0            GPIO_022
#define              ISP_CLK1            GPIO_023
#define              ISP_CLK2            GPIO_024
#define              ISP_SCL0            GPIO_025
#define              ISP_SDA0            GPIO_026
#define              ISP_SCL1            GPIO_027
#define              ISP_SDA1            GPIO_028
#define              ISP_SCL2            GPIO_029
#define              ISP_SDA2            GPIO_030
#define   UART0_RXD   GPIO_033
#define   UART0_TXD   GPIO_034
#define   UART0_RTS_N   GPIO_035
#define   UART0_CTS_N   GPIO_036
#define              I2C4_SCL            GPIO_037
#define              I2C4_SDA            GPIO_038
#define                SD_CLK            GPIO_041
#define                SD_CMD            GPIO_042
#define              SD_DATA0            GPIO_043
#define              SD_DATA1            GPIO_044
#define              SD_DATA2            GPIO_045
#define              SD_DATA3            GPIO_046
#define               SPI0_DI            GPIO_048
#define               SPI0_DO            GPIO_049
#define   SPI0_CLK   GPIO_050
#define   SPI0_CS0_N   GPIO_051
#define   SPI0_CS1_N   GPIO_052
#define   SPI0_CS2_N   GPIO_053
#define   EMMC_RST_N   GPIO_056
#define           UART1_CTS_N            GPIO_057
#define           UART1_RTS_N            GPIO_058
#define             UART1_RXD            GPIO_059
#define             UART1_TXD            GPIO_060
#define             SDIO0_CLK            GPIO_061
#define             SDIO0_CMD            GPIO_062
#define           SDIO0_DATA0            GPIO_063
#define           SDIO0_DATA1            GPIO_064
#define           SDIO0_DATA2            GPIO_065
#define           SDIO0_DATA3            GPIO_066
#define           UART6_CTS_N            GPIO_067
#define           UART6_RTS_N            GPIO_068
#define             UART6_RXD            GPIO_069
#define             UART6_TXD            GPIO_070
#define           UART3_CTS_N            GPIO_071
#define           UART3_RTS_N            GPIO_072
#define             UART3_RXD            GPIO_073
#define             UART3_TXD            GPIO_074
#define           UART4_CTS_N            GPIO_075
#define           UART4_RTS_N            GPIO_076
#define             UART4_RXD            GPIO_077
#define             UART4_TXD            GPIO_078
#define              PWM_OUT1            GPIO_079
#define         PMU_HKADC_SSI            GPIO_080
#define       PMU_AUXDAC0_SSI            GPIO_081
#define       PMU_AUXDAC1_SSI            GPIO_082
#define             USIM0_CLK            GPIO_083
#define             USIM0_RST            GPIO_084
#define            USIM0_DATA            GPIO_085
#define             USIM1_CLK            GPIO_086
#define             USIM1_RST            GPIO_087
#define            USIM1_DATA            GPIO_088
#define          LTE_INACTIVE            GPIO_089
#define         LTE_RX_ACTIVE            GPIO_090
#define         LTE_TX_ACTIVE            GPIO_091
#define          ISM_PRIORITY            GPIO_092
#define           CH0_AFC_PDM            GPIO_093
#define           CH0_APT_PDM            GPIO_094
#define         CH0_RF_RESETN            GPIO_095
#define            CH0_RF_SSI            GPIO_096
#define        CH0_RF_TCVR_ON            GPIO_097
#define           CH1_APT_PDM            GPIO_099
#define         CH1_RF_RESETN            GPIO_100
#define            CH1_RF_SSI            GPIO_101
#define        CH1_RF_TCVR_ON            GPIO_102
#define   ANTPA_SEL28   GPIO_103
#define   ANTPA_SEL29   GPIO_104
#define   ANTPA_SEL30   GPIO_105
#define          FE0_MIPI_CLK            GPIO_106
#define         FE0_MIPI_DATA            GPIO_107
#define          FE1_MIPI_CLK            GPIO_108
#define         FE1_MIPI_DATA            GPIO_109
#define            FLASH_MASK            GPIO_110
#define          GPS_BLANKING            GPIO_111
#define           ANTPA_SEL00            GPIO_112
#define           ANTPA_SEL01            GPIO_113
#define           ANTPA_SEL02            GPIO_114
#define           ANTPA_SEL03            GPIO_115
#define           ANTPA_SEL04            GPIO_116
#define           ANTPA_SEL05            GPIO_117
#define           ANTPA_SEL06            GPIO_118
#define           ANTPA_SEL07            GPIO_119
#define           ANTPA_SEL08            GPIO_120
#define           ANTPA_SEL09            GPIO_121
#define           ANTPA_SEL10            GPIO_122
#define           ANTPA_SEL11            GPIO_123
#define           ANTPA_SEL12            GPIO_124
#define           ANTPA_SEL13            GPIO_125
#define           ANTPA_SEL14            GPIO_126
#define           ANTPA_SEL15            GPIO_127
#define           ANTPA_SEL16            GPIO_128
#define           ANTPA_SEL17            GPIO_129
#define           ANTPA_SEL18            GPIO_130
#define           ANTPA_SEL19            GPIO_131
#define           ANTPA_SEL20            GPIO_132
#define           ANTPA_SEL21            GPIO_133
#define           ANTPA_SEL22            GPIO_134
#define           ANTPA_SEL23            GPIO_135
#define           ANTPA_SEL24            GPIO_136
#define           ANTPA_SEL25            GPIO_137
#define           ANTPA_SEL26            GPIO_138
#define           ANTPA_SEL27            GPIO_139
#define             SYSCLK_EN            GPIO_178
#define              CLK_OUT0            GPIO_179
#define              CLK_OUT1            GPIO_180
#define            BLPWM_CABC            GPIO_181
#define              BLPWM_BL            GPIO_182
#define              I2C0_SCL            GPIO_183
#define              I2C0_SDA            GPIO_184
#define              I2C2_SCL            GPIO_187
#define              I2C2_SDA            GPIO_188
#define           SLIMBUS_CLK            GPIO_189
#define          SLIMBUS_DATA            GPIO_190
#define      ISP_GPIO03_PRTRB            GPIO_215
#define      ISP_GPIO04_FTPWM            GPIO_216
#define      ISP_GPIO05_BKPWM            GPIO_217
#define        ISP_GPIO09_ENC            GPIO_218
#define        ISP_GPIO07_ENA            GPIO_219
#define        ISP_GPIO08_ENB            GPIO_220
#define            ISP_GPIO11            GPIO_221
#define            ISP_GPIO12            GPIO_222
#define            INVALID_VALUE_GPIO    (0xFFFFFFFF)

/* gpio of hi6402 chip */
#define DMIC_CLK0	GPIO_HI6402_0_1
#define DMIC_DATA0	GPIO_HI6402_0_2
#define DMIC_CLK1	GPIO_HI6402_0_3
#define DMIC_DATA1	GPIO_HI6402_0_4
#define SSI_DATA	GPIO_HI6402_0_5
#define IRQ_N		GPIO_HI6402_0_6
#define I2S1_SYNC	GPIO_HI6402_0_7

#define I2S1_CLK	GPIO_HI6402_1_0
#define I2S1_SDI	GPIO_HI6402_1_1
#define I2S1_SDO	GPIO_HI6402_1_2
#define I2S2_SYNC	GPIO_HI6402_1_3
#define I2S2_CLK	GPIO_HI6402_1_4
#define I2S2_SDI	GPIO_HI6402_1_5
#define I2S2_SDO	GPIO_HI6402_1_6
#define I2S3_SYNC	GPIO_HI6402_1_7

#define I2S3_CLK	GPIO_HI6402_2_0
#define I2S3_SDI	GPIO_HI6402_2_1
#define I2S3_SDO	GPIO_HI6402_2_2
#define I2S4_SYNC	GPIO_HI6402_2_3
#define I2S4_CLK	GPIO_HI6402_2_4
#define I2S4_SDI	GPIO_HI6402_2_5
#define I2S4_SDO	GPIO_HI6402_2_6
#define SPK_CLK		GPIO_HI6402_2_7

#define SPK_DATA	GPIO_HI6402_3_0

#endif
