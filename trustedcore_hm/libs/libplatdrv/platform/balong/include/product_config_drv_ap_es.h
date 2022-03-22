/* MD5: c49e64e0e753d28fbcfd513af9bd892e*/
/*
 * copyright (C) Huawei Technologies Co., Ltd. 2012-2015. All rights reserved.
 * foss@huawei.com
 *
 * If distributed as part of the Linux kernel, the following license terms
 * apply:
 *
 * * This program is free software; you can redistribute it and/or modify
 * * it under the terms of the GNU General Public License version 2 and
 * * only version 2 as published by the Free Software Foundation.
 * *
 * * This program is distributed in the hope that it will be useful,
 * * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * * GNU General Public License for more details.
 * *
 * * You should have received a copy of the GNU General Public License
 * * along with this program; if not, write to the Free Software
 * * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 * Otherwise, the following license terms apply:
 *
 * * Redistribution and use in source and binary forms, with or without
 * * modification, are permitted provided that the following conditions
 * * are met:
 * * 1) Redistributions of source code must retain the above copyright
 * *    notice, this list of conditions and the following disclaimer.
 * * 2) Redistributions in binary form must reproduce the above copyright
 * *    notice, this list of conditions and the following disclaimer in the
 * *    documentation and/or other materials provided with the distribution.
 * * 3) Neither the name of Huawei nor the names of its contributors may
 * *    be used to endorse or promote products derived from this software
 * *    without specific prior written permission.
 *
 * * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#if !defined(__PRODUCT_CONFIG_DRV_AP_ES_H__)
#define __PRODUCT_CONFIG_DRV_AP_ES_H__

#ifndef ENABLE_BUILD_VARS
#define ENABLE_BUILD_VARS 
#endif 

#ifndef CONFIG_DRV_CHIP_TYPE
#define CONFIG_DRV_CHIP_TYPE es 
#endif 

#ifndef ARCH_TYPE	
#define ARCH_TYPE	 3339 
#endif 

#ifndef KERNEL_USE_MINIMUM_INITRAMFS
#endif 

#ifndef OS_LINUX_PRODUCT_NAME
#define OS_LINUX_PRODUCT_NAME hi9510_udp_defconfig 
#endif 

#ifndef OS_LINUX_BASE_PRODUCT_NAME
#define OS_LINUX_BASE_PRODUCT_NAME hi9510_base_defconfig 
#endif 

#ifndef OS_LINUX_SLT_PRODUCT_NAME
#define OS_LINUX_SLT_PRODUCT_NAME hi9510_udp_slt_defconfig 
#endif 

#ifndef TARGET_BALONG_PRODUCT
#define TARGET_BALONG_PRODUCT hi9510_udp 
#endif 

#ifndef CONFIG_ARM64
#define CONFIG_ARM64 
#endif 

#ifndef EMU_RAMDISK_FOR_ENG
#define EMU_RAMDISK_FOR_ENG 
#endif 

#ifndef BSP_CONFIG_EDA
#endif 

#ifndef BSP_CONFIG_PACKBIST
#endif 

#ifndef BSP_CONFIG_EXMBIST
#endif 

#ifndef BSP_CONFIG_EMU
#endif 

#ifndef BSP_CONFIG_NOT_DDR_BYPASSPLL
#endif 

#ifndef BSP_CONFIG_EMU_DDR_START
#endif 

#ifndef BSP_CONFIG_EMU_NANDC_MEM
#endif 

#ifndef BSP_CONFIG_EMU_FASTUART
#endif 

#ifndef BSP_CONFIG_EMU_UART_BAUD
#define BSP_CONFIG_EMU_UART_BAUD 1000000 
#endif 

#ifndef BSP_CONFIG_ZEBU_EMU_TIMER_CLK
#endif 

#ifndef BSP_CONFIG_ZEBU_EMU_TIMER_CLKFREQ
#define BSP_CONFIG_ZEBU_EMU_TIMER_CLKFREQ 1000000 
#endif 

#ifndef CONFIG_HIBOOT_DEBUG
#endif 

#ifndef CONFIG_SRAM_SECURE
#define CONFIG_SRAM_SECURE 
#endif 

#ifndef CONFIG_OF
#define CONFIG_OF 
#endif 

#ifndef CONFIG_CCPU_FIQ_SMP
#endif 

#ifndef CONFIG_NVIM
#define CONFIG_NVIM 
#endif 

#ifndef FEATURE_NV_EMMC_ON
#define FEATURE_NV_EMMC_ON 
#endif 

#ifndef NV_IMG_BOOT_CHECK_REBOOT_ON
#define NV_IMG_BOOT_CHECK_REBOOT_ON 
#endif 

#ifndef FEATURE_NV_SEC_ON
#define FEATURE_NV_SEC_ON 
#endif 

#ifndef CONFIG_NV_FUSION
#define CONFIG_NV_FUSION 
#endif 

#ifndef CONFIG_NV_FUSION_MSG
#define CONFIG_NV_FUSION_MSG 
#endif 

#ifndef NV_IMG_UNIFIED
#define NV_IMG_UNIFIED 
#endif 

#ifndef FEATURE_NVA_ON
#define FEATURE_NVA_ON 
#endif 

#ifndef CONFIG_MAILBOX_TYPE
#endif 

#ifndef CONFIG_HIFI_MAILBOX
#endif 

#ifndef FEATURE_CONFIG_P532_DALLAS
#endif 

#ifndef ENABLE_BUILD_OM
#define ENABLE_BUILD_OM 
#endif 

#ifndef ENABLE_BUILD_PRINT
#define ENABLE_BUILD_PRINT 
#endif 

#ifndef FEATURE_OM_PHONE
#endif 

#ifndef ENABLE_BUILD_SYSVIEW
#endif 

#ifndef ENABLE_BUILD_CPUVIEW
#endif 

#ifndef ENABLE_BUILD_MEMVIEW
#endif 

#ifndef ENABLE_BUILD_UTRACE
#endif 

#ifndef ENABLE_BUILD_SOCP
#define ENABLE_BUILD_SOCP 
#endif 

#ifndef CONFIG_DEFLATE
#endif 

#ifndef SOCP_V300
#define SOCP_V300 
#endif 

#ifndef CONFIG_HOMI
#define CONFIG_HOMI 
#endif 

#ifndef FEATURE_HISOCKET
#define FEATURE_HISOCKET FEATURE_ON 
#endif 

#ifndef FEATURE_SVLSOCKET
#endif 

#ifndef CONFIG_DIAG_SYSTEM
#define CONFIG_DIAG_SYSTEM 
#endif 

#ifndef DIAG_SYSTEM_5G
#define DIAG_SYSTEM_5G 
#endif 

#ifndef DIAG_SYSTEM_FUSION
#define DIAG_SYSTEM_FUSION 
#endif 

#ifndef CONFIG_APPLOG
#endif 

#ifndef CONFIG_SECDEBUG_VERIFY
#define CONFIG_SECDEBUG_VERIFY 
#endif 

#ifndef CONFIG_CCPUDEBUG
#define CONFIG_CCPUDEBUG 
#endif 

#ifndef CONFIG_BALONG_CORESIGHT
#define CONFIG_BALONG_CORESIGHT 
#endif 

#ifndef CONFIG_OCD
#define CONFIG_OCD 
#endif 

#ifndef CONFIG_WATCHPOINT
#define CONFIG_WATCHPOINT 
#endif 

#ifndef FEATURE_HDS_PRINTLOG
#define FEATURE_HDS_PRINTLOG FEATURE_OFF 
#endif 

#ifndef FEATURE_HDS_TRANSLOG
#define FEATURE_HDS_TRANSLOG FEATURE_OFF 
#endif 

#ifndef FEATURE_SRE_PRINT_SLICE
#define FEATURE_SRE_PRINT_SLICE FEATURE_ON 
#endif 

#ifndef FEATURE_SRE_PRINT_RTC
#define FEATURE_SRE_PRINT_RTC FEATURE_OFF 
#endif 

#ifndef CONFIG_BUS_ERR_AP
#define CONFIG_BUS_ERR_AP 
#endif 

#ifndef CONFIG_NOC_AP
#define CONFIG_NOC_AP 
#endif 

#ifndef CONFIG_PDLOCK_AP
#define CONFIG_PDLOCK_AP 
#endif 

#ifndef CONFIG_MID
#define CONFIG_MID 
#endif 

#ifndef CONFIG_HISI_AMON_DEBUGFS
#define CONFIG_HISI_AMON_DEBUGFS 
#endif 

#ifndef ENABLE_AMON_SOC
#define ENABLE_AMON_SOC 
#endif 

#ifndef CONFIG_DMSS
#define CONFIG_DMSS 
#endif 

#ifndef CONFIG_MODEM_DMSS_3_0
#define CONFIG_MODEM_DMSS_3_0 
#endif 

#ifndef FEATURE_SAMPLE_LTE_CHAN 			
#define FEATURE_SAMPLE_LTE_CHAN 			 FEATURE_OFF 
#endif 

#ifndef CONFIG_MBB_AP_SCI
#define CONFIG_MBB_AP_SCI 
#endif 

#ifndef CONFIG_MBB_SIMHOTPLUG
#define CONFIG_MBB_SIMHOTPLUG 
#endif 

#ifndef FEATURE_SCI_PROTOL_T1
#define FEATURE_SCI_PROTOL_T1 FEATURE_OFF 
#endif 

#ifndef FEATURE_SCI_ESIM
#define FEATURE_SCI_ESIM FEATURE_OFF 
#endif 

#ifndef CONFIG_SC
#endif 

#ifndef CONFIG_BALONG_RDR
#define CONFIG_BALONG_RDR 
#endif 

#ifndef CONFIG_RDR_BACK_UP
#endif 

#ifndef CONFIG_VERSION_STUB
#endif 

#ifndef HW_VERSION_STUB
#define HW_VERSION_STUB 0x78000008 
#endif 

#ifndef BOARD_VERSION_STUB
#define BOARD_VERSION_STUB 0x0 
#endif 

#ifndef CONFIG_ACORE_WDT
#define CONFIG_ACORE_WDT 
#endif 

#ifndef CONFIG_WDT_BOOT
#endif 

#ifndef FEATURE_CHR_OM
#define FEATURE_CHR_OM FEATURE_OFF 
#endif 

#ifndef FLASH_PTABLE_OFFSET
#define FLASH_PTABLE_OFFSET 0x5A00000 
#endif 

#ifndef FLASH_PTABLE_SIZE
#define FLASH_PTABLE_SIZE 0x100000 
#endif 

#ifndef CONFIG_GPIO_PL061
#define CONFIG_GPIO_PL061 
#endif 

#ifndef CONFIG_GPIO_EXPANDER
#endif 

#ifndef PINCTRL_CONFIG_BALONG
#define PINCTRL_CONFIG_BALONG 
#endif 

#ifndef CONFIG_COMPRESS_CCORE_IMAGE
#define CONFIG_COMPRESS_CCORE_IMAGE 
#endif 

#ifndef CONFIG_ZSTD_DECOMPRESS
#endif 

#ifndef BSP_HAS_SEC_FEATURE
#endif 

#ifndef CONFIG_SEC_BOOT_BALONG
#endif 

#ifndef USE_USBLOADER_MERGE 			
#endif 

#ifndef BSP_ENBALE_PACK_IMAGE			
#endif 

#ifndef BSP_USB_BURN				
#define BSP_USB_BURN				 
#endif 

#ifndef USBLOADER_ONLY_XLOADER
#define USBLOADER_ONLY_XLOADER 
#endif 

#ifndef FEATURE_DELAY_MODEM_INIT
#define FEATURE_DELAY_MODEM_INIT FEATURE_ON 
#endif 

#ifndef CONFIG_HIFI
#define CONFIG_HIFI 
#endif 

#ifndef BSP_CONFIG_EMU_HIFI
#endif 

#ifndef CONFIG_ADC
#define CONFIG_ADC 
#endif 

#ifndef CONFIG_HKADC
#define CONFIG_HKADC 
#endif 

#ifndef CONFIG_MIPI
#endif 

#ifndef CONFIG_CROSS_MIPI
#endif 

#ifndef CONFIG_LEDS_CCORE
#endif 

#ifndef CONFIG_FB_SPI_BALONG
#endif 

#ifndef CONFIG_FB_EMI_BALONG
#endif 

#ifndef CONFIG_FB_1_4_5_INCH_BALONG
#endif 

#ifndef CONFIG_FB_2_4_INCH_BALONG
#endif 

#ifndef CONFIG_PCIE_CFG
#define CONFIG_PCIE_CFG 
#endif 

#ifndef CONFIG_PCIE_DWC_5_40_A
#define CONFIG_PCIE_DWC_5_40_A 
#endif 

#ifndef CONFIG_TRUSTZONE
#define CONFIG_TRUSTZONE 
#endif 

#ifndef CONFIG_TRUSTZONE_HM
#define CONFIG_TRUSTZONE_HM 
#endif 

#ifndef CONFIG_SFLASH
#endif 

#ifndef CONFIG_EMMC_BOOT
#endif 

#ifndef CONFIG_UBIFS_BOOT
#define CONFIG_UBIFS_BOOT 
#endif 

#ifndef CONFIG_AUDIO
#define CONFIG_AUDIO m 
#endif 

#ifndef CONFIG_SOUND_DEMO
#define CONFIG_SOUND_DEMO 
#endif 

#ifndef CONFIG_EFUSE
#define CONFIG_EFUSE 
#endif 

#ifndef CONFIG_DX_LIB
#define CONFIG_DX_LIB 
#endif 

#ifndef CONFIG_DESIGNWARE_I2C
#define CONFIG_DESIGNWARE_I2C 
#endif 

#ifndef CONFIG_SPI_SECONDARY
#endif 

#ifndef CONFIG_SPI_HISI
#endif 

#ifndef CONFIG_MLOADER
#define CONFIG_MLOADER 
#endif 

#ifndef CONFIG_LOAD_SEC_IMAGE
#define CONFIG_LOAD_SEC_IMAGE 
#endif 

#ifndef CONFIG_RFILE_ON
#define CONFIG_RFILE_ON 
#endif 

#ifndef CONFIG_RFILE_USER
#define CONFIG_RFILE_USER 
#endif 

#ifndef STACK_CANARY_COMPILE
#define STACK_CANARY_COMPILE 
#endif 

#ifndef CONFIG_SYSBOOT_PARA
#define CONFIG_SYSBOOT_PARA 
#endif 

#ifndef CONFIG_SYSBOOT_PARA_DEBUG
#define CONFIG_SYSBOOT_PARA_DEBUG 
#endif 

#ifndef CONFIG_DIRECT_BOOT
#endif 

#ifndef CONFIG_ACTRL_SMP
#define CONFIG_ACTRL_SMP 
#endif 

#ifndef CONFIG_BALONG_MBB_AP
#define CONFIG_BALONG_MBB_AP 
#endif 

#ifndef CONFIG_M535_EMU
#endif 

#ifndef CONFIG_USE_TIMER_STAMP
#endif 

#ifndef CONFIG_HIBOOT_UART_NUM
#define CONFIG_HIBOOT_UART_NUM 0 
#endif 

#ifndef HIBOOT_HAC_UART_ENABLE
#endif 

#ifndef HIBOOT_CCORE_UART_ENABLE
#define HIBOOT_CCORE_UART_ENABLE 
#endif 

#ifndef BSP_CONFIG_EMU_MCORE_DTB
#endif 

#ifndef CONFIG_BALONG_CHIP_VERSION
#define CONFIG_BALONG_CHIP_VERSION es 
#endif 

#ifndef BSP_CONFIG_EMU_NO_PMU
#define BSP_CONFIG_EMU_NO_PMU 
#endif 

#ifndef BSP_CONFIG_EMU_NO_USB
#endif 

#ifndef BSP_CONFIG_EMU_BOOT
#define BSP_CONFIG_EMU_BOOT 
#endif 

#ifndef CONFIG_MODULE_VIC
#endif 

#ifndef CONFIG_AT_UART
#define CONFIG_AT_UART 
#endif 

#ifndef CONFIG_CSHELL
#endif 

#ifndef CONFIG_UART_SHELL
#define CONFIG_UART_SHELL 
#endif 

#ifndef CONFIG_OS_INCLUDE_SHELL
#define CONFIG_OS_INCLUDE_SHELL 
#endif 

#ifndef CONFIG_GNSS_BALONG
#define CONFIG_GNSS_BALONG 
#endif 

#ifndef CONFIG_GNSS_MSG_BALONG
#define CONFIG_GNSS_MSG_BALONG 
#endif 

#ifndef CONFIG_POSITION_SERVICE
#define CONFIG_POSITION_SERVICE 
#endif 

#ifndef CONFIG_SHELL_SYMBOL_REG
#define CONFIG_SHELL_SYMBOL_REG 
#endif 

#ifndef DTS_STATIC_MEM_SIZE
#define DTS_STATIC_MEM_SIZE 204800 
#endif 

#ifndef CONFIG_IPCM_USE_FPGA_VIC
#endif 

#ifndef CONFIG_MODULE_TIMER
#define CONFIG_MODULE_TIMER 
#endif 

#ifndef CONFIG_PWC_MNTN_CCORE
#endif 

#ifndef CONFIG_HWADP
#endif 

#ifndef CONFIG_MEM
#endif 

#ifndef CONFIG_TCXO_BALONG
#endif 

#ifndef CONFIG_MODULE_BUSSTRESS
#endif 

#ifndef CONFIG_MALLOC_UNIFIED
#define CONFIG_MALLOC_UNIFIED 
#endif 

#ifndef CONFIG_AXIMEM_BALONG
#endif 

#ifndef CONFIG_SHARED_MEMORY
#define CONFIG_SHARED_MEMORY 
#endif 

#ifndef CONFIG_NMI
#define CONFIG_NMI 
#endif 

#ifndef CONFIG_DDR_PROTECT
#define CONFIG_DDR_PROTECT 
#endif 

#ifndef CONFIG_DDR_PROTECT_DEBUG
#endif 

#ifndef HIBOOT_RESERVE_DDR
#define HIBOOT_RESERVE_DDR 
#endif 

#ifndef CONFIG_MEMORY_LAYOUT
#define CONFIG_MEMORY_LAYOUT 
#endif 

#ifndef CONFIG_BALONG_MODEM_RESET
#define CONFIG_BALONG_MODEM_RESET 
#endif 

#ifndef CONFIG_DRAM_SIZE
#define CONFIG_DRAM_SIZE 
#endif 

#ifndef CONFIG_IPF
#endif 

#ifndef CONFIG_PSAM
#endif 

#ifndef CONFIG_CIPHER
#endif 

#ifndef CONFIG_NEW_PLATFORM
#define CONFIG_NEW_PLATFORM 
#endif 

#ifndef CONFIG_CIPHER_NEW
#endif 

#ifndef CONFIG_ESPE
#define CONFIG_ESPE 
#endif 

#ifndef CONFIG_BALONG_ESPE_FW
#define CONFIG_BALONG_ESPE_FW 
#endif 

#ifndef CONFIG_ESPE_DIRECT_FW
#define CONFIG_ESPE_DIRECT_FW 
#endif 

#ifndef CONFIG_BALONG_ESPE_DFS
#define CONFIG_BALONG_ESPE_DFS 
#endif 

#ifndef CONFIG_BALONG_ESPE
#define CONFIG_BALONG_ESPE 
#endif 

#ifndef CONFIG_EIPF
#define CONFIG_EIPF 
#endif 

#ifndef CONFIG_WAN
#define CONFIG_WAN 
#endif 

#ifndef CONFIG_IPF_VESION
#define CONFIG_IPF_VESION 2 
#endif 

#ifndef CONFIG_IPF_ADQ_LEN
#define CONFIG_IPF_ADQ_LEN 3 
#endif 

#ifndef CONFIG_IPF_PROPERTY_MBB
#define CONFIG_IPF_PROPERTY_MBB 
#endif 

#ifndef CONFIG_BALONG_TRANS_REPORT
#define CONFIG_BALONG_TRANS_REPORT 
#endif 

#ifndef CONFIG_TRANS_REPORT_5010
#define CONFIG_TRANS_REPORT_5010 
#endif 

#ifndef CONFIG_USB_DWC3_VBUS_DISCONNECT
#define CONFIG_USB_DWC3_VBUS_DISCONNECT 
#endif 

#ifndef USB3_SYNOPSYS_PHY
#endif 

#ifndef CONFIG_USB_FORCE_HIGHSPEED
#define CONFIG_USB_FORCE_HIGHSPEED 
#endif 

#ifndef HIBOOT_ADB
#define HIBOOT_ADB 
#endif 

#ifndef CONFIG_SN_SUPPORT
#define CONFIG_SN_SUPPORT 
#endif 

#ifndef CONFIG_DIEID_TRANS_SN
#endif 

#ifndef CONFIG_NV_TRANS_SN
#endif 

#ifndef CONFIG_MAA_BALONG
#define CONFIG_MAA_BALONG 
#endif 

#ifndef CONFIG_MAA_V2
#define CONFIG_MAA_V2 
#endif 

#ifndef SPEV300_SUPPORT
#define SPEV300_SUPPORT 
#endif 

#ifndef CONFIG_VDEV
#define CONFIG_VDEV 
#endif 

#ifndef CONFIG_VDEV_PHONE
#endif 

#ifndef CONFIG_USB_RELAY
#define CONFIG_USB_RELAY 
#endif 

#ifndef CONFIG_USB_PPP_NDIS
#define CONFIG_USB_PPP_NDIS 
#endif 

#ifndef ENABLE_TEST_CODE
#endif 

#ifndef CONFIG_LLT_MDRV
#define CONFIG_LLT_MDRV 
#endif 

#ifndef CONFIG_ECDC
#define CONFIG_ECDC 
#endif 

#ifndef CONFIG_EICC_V200
#define CONFIG_EICC_V200 
#endif 

#ifndef CONFIG_BALONG_MSG
#define CONFIG_BALONG_MSG 
#endif 

#ifndef CONFIG_ICC
#endif 

#ifndef CONFIG_MODULE_IPC_FUSION
#define CONFIG_MODULE_IPC_FUSION 
#endif 

#ifndef CONFIG_INIT_EXPECTED_TZPC
#define CONFIG_INIT_EXPECTED_TZPC 
#endif 

#ifndef MDRV_TEST
#endif 

#ifndef CONFIG_PMU_DR
#define CONFIG_PMU_DR 
#endif 

#ifndef CONFIG_CLK_HIBOOT_STACK
#define CONFIG_CLK_HIBOOT_STACK 
#endif 

#ifndef BSP_CONFIG_EMU_LPMCU
#endif 

#ifndef THREE_DFS_CTRL_REG
#define THREE_DFS_CTRL_REG 
#endif 

#ifndef MDRV_ACC_CLK_LLT
#define MDRV_ACC_CLK_LLT 
#endif 

#ifndef CONFIG_PMU_VERSION
#define CONFIG_PMU_VERSION PMU_V200 
#endif 

#ifndef CONFIG_SYSCTRL
#define CONFIG_SYSCTRL 
#endif 

#ifndef FEATURE_THERMAL
#endif 

#ifndef CONFIG_BL31
#define CONFIG_BL31 
#endif 

#ifndef CONFIG_MAX_FREQ
#define CONFIG_MAX_FREQ 
#endif 

#ifndef FEATURE_THERMAL
#define FEATURE_THERMAL 
#endif 

#ifndef CONFIG_COUL
#endif 

#ifndef CONFIG_SMMU
#define CONFIG_SMMU 
#endif 

#ifndef CONFIG_FB_CUST
#define CONFIG_FB_CUST 
#endif 

#ifndef CONFIG_HEATING_CALIBRATION
#define CONFIG_HEATING_CALIBRATION 
#endif 

#ifndef CONFIG_USB_V100
#define CONFIG_USB_V100 
#endif 

#ifndef CONFIG_SYSBUS
#define CONFIG_SYSBUS 
#endif 

#ifndef FEATURE_NV_PARTRION_MULTIPLEX
#define FEATURE_NV_PARTRION_MULTIPLEX FEATURE_ON 
#endif 

#ifndef CONFIG_TSPCCPU_HAS_TCM
#endif 

#ifndef LINUX_KERNEL
#define LINUX_KERNEL kernel 
#endif 

#ifndef ATE_VECTOR
#endif 

#ifndef LARGE_KERNEL_IMAGE
#define LARGE_KERNEL_IMAGE 
#endif 

#ifndef CONFIG_RAMDISK_OFFSET_SIZE
#define CONFIG_RAMDISK_OFFSET_SIZE 0x2000000 
#endif 

#ifndef CONFIG_MODEM_FULL_DUMP
#define CONFIG_MODEM_FULL_DUMP 
#endif 

#ifndef CONFIG_MODEM_MINI_DUMP
#define CONFIG_MODEM_MINI_DUMP 
#endif 

#ifndef CONFIG_DUMP_LOG_ESCAPE_FIQ
#endif 

#ifndef CONFIG_CHARGER_HI6526
#define CONFIG_CHARGER_HI6526 
#endif 

#endif /*__PRODUCT_CONFIG_H__*/ 
