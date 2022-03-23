/* MD5: 97332f2e1ce0bd36868c262be3e750d9*/
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

#if !defined(__PRODUCT_CONFIG_DRV_MCU_ES_H__)
#define __PRODUCT_CONFIG_DRV_MCU_ES_H__

#ifndef ENABLE_BUILD_VARS
#define ENABLE_BUILD_VARS 
#endif 

#ifndef BSP_CONFIG_NOT_DDR_BYPASSPLL
#endif 

#ifndef BSP_CONFIG_EMU
#endif 

#ifndef BSP_CONFIG_EDA
#endif 

#ifndef BSP_CONFIG_PACKBIST
#endif 

#ifndef BSP_CONFIG_EXMBIST
#endif 

#ifndef BSP_CONFIG_EMU_DDR_START
#endif 

#ifndef CONFIG_NMI
#define CONFIG_NMI 
#endif 

#ifndef CONFIG_MODULE_TIMER
#define CONFIG_MODULE_TIMER 
#endif 

#ifndef CONFIG_UART_SHELL
#define CONFIG_UART_SHELL 
#endif 

#ifndef CONFIG_OS_INCLUDE_SHELL
#define CONFIG_OS_INCLUDE_SHELL 
#endif 

#ifndef BSP_CONFIG_EMU_MCORE_DTB
#endif 

#ifndef CONFIG_BALONG_CHIP_VERSION
#define CONFIG_BALONG_CHIP_VERSION es 
#endif 

#ifndef TARGET_BALONG_PRODUCT
#define TARGET_BALONG_PRODUCT hi9510_udp 
#endif 

#ifndef CONFIG_NV_FUSION
#define CONFIG_NV_FUSION 
#endif 

#ifndef FEATURE_NVA_ON
#define FEATURE_NVA_ON 
#endif 

#ifndef ENABLE_BUILD_PRINT
#define ENABLE_BUILD_PRINT 
#endif 

#ifndef FEATURE_HDS_PRINTLOG
#define FEATURE_HDS_PRINTLOG FEATURE_ON 
#endif 

#ifndef FEATURE_HDS_TRANSLOG
#define FEATURE_HDS_TRANSLOG FEATURE_ON 
#endif 

#ifndef FEATURE_SRE_PRINT_SLICE
#define FEATURE_SRE_PRINT_SLICE FEATURE_ON 
#endif 

#ifndef FEATURE_SRE_PRINT_RTC
#define FEATURE_SRE_PRINT_RTC FEATURE_OFF 
#endif 

#ifndef ENABLE_BUILD_OM
#define ENABLE_BUILD_OM 
#endif 

#ifndef CONFIG_MODEM_MINI_DUMP
#define CONFIG_MODEM_MINI_DUMP 
#endif 

#ifndef CONFIG_MODEM_FULL_DUMP
#define CONFIG_MODEM_FULL_DUMP 
#endif 

#ifndef ENABLE_BUILD_SOCP
#define ENABLE_BUILD_SOCP 
#endif 

#ifndef SOCP_V300
#define SOCP_V300 
#endif 

#ifndef DIAG_SYSTEM_5G
#define DIAG_SYSTEM_5G 
#endif 

#ifndef CONFIG_CCPUDEBUG
#define CONFIG_CCPUDEBUG 
#endif 

#ifndef CONFIG_PTABLE_LEGACY
#define CONFIG_PTABLE_LEGACY 
#endif 

#ifndef FLASH_PTABLE_OFFSET
#define FLASH_PTABLE_OFFSET 0x5A00000 
#endif 

#ifndef FLASH_PTABLE_SIZE
#define FLASH_PTABLE_SIZE 0x100000 
#endif 

#ifndef FLASH_PTABLE_PART_NUM
#define FLASH_PTABLE_PART_NUM 0x8 
#endif 

#ifndef CONFIG_ONOFF
#define CONFIG_ONOFF 
#endif 

#ifndef BSP_USB_BURN
#define BSP_USB_BURN 
#endif 

#ifndef USBLOADER_ONLY_XLOADER
#define USBLOADER_ONLY_XLOADER 
#endif 

#ifndef CONFIG_ADC
#define CONFIG_ADC 
#endif 

#ifndef CONFIG_HIFI_FUSION
#define CONFIG_HIFI_FUSION 
#endif 

#ifndef STACK_CANARY_COMPILE
#define STACK_CANARY_COMPILE 
#endif 

#ifndef CONFIG_EFUSE
#define CONFIG_EFUSE 
#endif 

#ifndef PINCTRL_CONFIG_BALONG
#define PINCTRL_CONFIG_BALONG 
#endif 

#ifndef CONFIG_SYSBOOT_PARA
#define CONFIG_SYSBOOT_PARA 
#endif 

#ifndef CONFIG_SYSBOOT_PARA_DEBUG
#define CONFIG_SYSBOOT_PARA_DEBUG 
#endif 

#ifndef CONFIG_MLOADER
#define CONFIG_MLOADER 
#endif 

#ifndef CONFIG_LOAD_SEC_IMAGE
#define CONFIG_LOAD_SEC_IMAGE 
#endif 

#ifndef CONFIG_SHARED_MEMORY
#define CONFIG_SHARED_MEMORY 
#endif 

#ifndef CONFIG_OF
#define CONFIG_OF 
#endif 

#ifndef CONFIG_MEMORY_LAYOUT
#define CONFIG_MEMORY_LAYOUT 
#endif 

#ifndef CONFIG_BALONG_MODEM_RESET
#define CONFIG_BALONG_MODEM_RESET 
#endif 

#ifndef CONFIG_DDR_PROTECT_XLOADER
#define CONFIG_DDR_PROTECT_XLOADER 
#endif 

#ifndef CONFIG_EIPF_V2
#define CONFIG_EIPF_V2 
#endif 

#ifndef CONFIG_ESPE
#define CONFIG_ESPE 
#endif 

#ifndef SPEV300_SUPPORT
#define SPEV300_SUPPORT 
#endif 

#ifndef ESPE_MCORE_DEBUG
#define ESPE_MCORE_DEBUG 
#endif 

#ifndef CONFIG_MAAV2_BALONG
#define CONFIG_MAAV2_BALONG 
#endif 

#ifndef CONFIG_EMU_DDR
#endif 

#ifndef CONFIG_DDR_AVS
#endif 

#ifndef CONFIG_DDR_AVS_PASENSOR
#endif 

#ifndef CONFIG_DDR_AVS_TEST
#endif 

#ifndef DDR_DVFS_SR_9510
#define DDR_DVFS_SR_9510 
#endif 

#ifndef CONFIG_MODULE_IPC_FUSION
#define CONFIG_MODULE_IPC_FUSION 
#endif 

#ifndef CONFIG_EICC_V200
#define CONFIG_EICC_V200 
#endif 

#ifndef CONFIG_BALONG_MSG
#define CONFIG_BALONG_MSG 
#endif 

#ifndef CONFIG_UCE_IMAGE_COMPILE
#define CONFIG_UCE_IMAGE_COMPILE 
#endif 

#ifndef CONFIG_UCE_USER_VERSION
#endif 

#ifndef CONFIG_BALONG_MBB_AP
#define CONFIG_BALONG_MBB_AP 
#endif 

#ifndef LPMCU_DRAM_WINDOW
#define LPMCU_DRAM_WINDOW 0x20000000 
#endif 

#ifndef CONFIG_PMU_VERSION
#define CONFIG_PMU_VERSION PMU_V200 
#endif 

#ifndef CONFIG_PMCTRL_VERSION
#define CONFIG_PMCTRL_VERSION PMCTRL_V200 
#endif 

#ifndef CONFIG_FUSION_MDM_START
#define CONFIG_FUSION_MDM_START 
#endif 

#ifndef CONFIG_SYSCTRL
#define CONFIG_SYSCTRL 
#endif 

#ifndef CONFIG_GET_SYSTEM_STATUS
#define CONFIG_GET_SYSTEM_STATUS 
#endif 

#ifndef CONFIG_TSENSOR
#define CONFIG_TSENSOR 
#endif 

#ifndef CONFIG_TSENSOR_MSG
#define CONFIG_TSENSOR_MSG 
#endif 

#ifndef CONFIG_BL31
#define CONFIG_BL31 
#endif 

#ifndef CONFIG_FUSION_M3PM
#define CONFIG_FUSION_M3PM 
#endif 

#ifndef CONFIG_FUSION_M3PM_TEST
#define CONFIG_FUSION_M3PM_TEST 
#endif 

#ifndef M3PM_LOG_AP_SHOW
#define M3PM_LOG_AP_SHOW 
#endif 

#ifndef XLOADER_CONFIG
#define XLOADER_CONFIG 
#endif 

#ifndef FEATURE_THERMAL
#define FEATURE_THERMAL 
#endif 

#ifndef CONFIG_FUSION_AVS
#define CONFIG_FUSION_AVS 
#endif 

#ifndef MCORE_MPU_ENABLE
#define MCORE_MPU_ENABLE 
#endif 

#ifndef CONGIG_XLOADER_USB
#define CONGIG_XLOADER_USB 
#endif 

#ifndef CONFIG_XLOADER_USB_BSN
#define CONFIG_XLOADER_USB_BSN 
#endif 

#ifndef CONFIG_SN_SUPPORT
#define CONFIG_SN_SUPPORT 
#endif 

#ifndef CONFIG_USB_V100
#define CONFIG_USB_V100 
#endif 

#ifndef CONFIG_SMMU
#define CONFIG_SMMU 
#endif 

#endif /*__PRODUCT_CONFIG_H__*/ 
