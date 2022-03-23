/* MD5: 7bbb15ab33073fa5172237a9e35c7938*/
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

#if !defined(__PRODUCT_CONFIG_DRV_TSP_H__)
#define __PRODUCT_CONFIG_DRV_TSP_H__

#ifndef ENABLE_BUILD_VARS
#define ENABLE_BUILD_VARS 
#endif 

#ifndef CONFIG_DRV_CHIP_TYPE
#define CONFIG_DRV_CHIP_TYPE cs 
#endif 

#ifndef CCPU_OS
#define CCPU_OS RTOSCK_SMP 
#endif 

#ifndef CCPU_TSP_OS
#define CCPU_TSP_OS RTOSCK_TSP_V150 
#endif 

#ifndef CCPU_ARCH
#define CCPU_ARCH HITSP_V150 
#endif 

#ifndef CCPU_TSP_OS_PATH
#define CCPU_TSP_OS_PATH tspv150 
#endif 

#ifndef CCPU_TVP_OS
#define CCPU_TVP_OS RTOSCK_TVP_V100 
#endif 

#ifndef HCC_VERSION
#define HCC_VERSION 7.3 
#endif 

#ifndef CCPU_CORE_NUM
#define CCPU_CORE_NUM 12 
#endif 

#ifndef CCPU_RUN_COREMASK
#define CCPU_RUN_COREMASK 0xfff 
#endif 

#ifndef CCPU_RUN_LOGIC_COREMASK
#define CCPU_RUN_LOGIC_COREMASK 0xfff 
#endif 

#ifndef CCPU_DSS_NUM
#define CCPU_DSS_NUM 3 
#endif 

#ifndef TSP_DSS0_CORE_NUM
#define TSP_DSS0_CORE_NUM 4 
#endif 

#ifndef TSP_DSS1_CORE_NUM
#define TSP_DSS1_CORE_NUM 4 
#endif 

#ifndef TSP_DSS2_CORE_NUM
#define TSP_DSS2_CORE_NUM 4 
#endif 

#ifndef TSP_DSS3_CORE_NUM
#define TSP_DSS3_CORE_NUM 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN_NUM
#define MODEM_SCHEDULE_DOMAIN_NUM 2 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN0
#define MODEM_SCHEDULE_DOMAIN0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN0_TYPE
#define MODEM_SCHEDULE_DOMAIN0_TYPE 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN0_COREMASK
#define MODEM_SCHEDULE_DOMAIN0_COREMASK 0xF 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN0_COREBEGIN
#define MODEM_SCHEDULE_DOMAIN0_COREBEGIN 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN0_CORENUM
#define MODEM_SCHEDULE_DOMAIN0_CORENUM 4 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN1
#define MODEM_SCHEDULE_DOMAIN1 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN1_TYPE
#define MODEM_SCHEDULE_DOMAIN1_TYPE 1 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN1_COREMASK
#define MODEM_SCHEDULE_DOMAIN1_COREMASK 0xFF0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN1_COREBEGIN
#define MODEM_SCHEDULE_DOMAIN1_COREBEGIN 4 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN1_CORENUM
#define MODEM_SCHEDULE_DOMAIN1_CORENUM 8 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN2
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN2_TYPE
#define MODEM_SCHEDULE_DOMAIN2_TYPE 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN2_COREMASK
#define MODEM_SCHEDULE_DOMAIN2_COREMASK 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN2_COREBEGIN
#define MODEM_SCHEDULE_DOMAIN2_COREBEGIN 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN2_CORENUM
#define MODEM_SCHEDULE_DOMAIN2_CORENUM 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN3
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN3_TYPE
#define MODEM_SCHEDULE_DOMAIN3_TYPE 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN3_COREMASK
#define MODEM_SCHEDULE_DOMAIN3_COREMASK 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN3_COREBEGIN
#define MODEM_SCHEDULE_DOMAIN3_COREBEGIN 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN3_CORENUM
#define MODEM_SCHEDULE_DOMAIN3_CORENUM 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN4
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN4_TYPE
#define MODEM_SCHEDULE_DOMAIN4_TYPE 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN4_COREMASK
#define MODEM_SCHEDULE_DOMAIN4_COREMASK 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN4_COREBEGIN
#define MODEM_SCHEDULE_DOMAIN4_COREBEGIN 0 
#endif 

#ifndef MODEM_SCHEDULE_DOMAIN4_CORENUM
#define MODEM_SCHEDULE_DOMAIN4_CORENUM 0 
#endif 

#ifndef CONFIG_DRV_SCHEDULE_DOMAIN
#define CONFIG_DRV_SCHEDULE_DOMAIN MODEM_SCHEDULE_DOMAIN0_COREMASK 
#endif 

#ifndef CONFIG_PS_SCHEDULE_DOMAIN
#define CONFIG_PS_SCHEDULE_DOMAIN MODEM_SCHEDULE_DOMAIN0_COREMASK 
#endif 

#ifndef CONFIG_PHY_SCHEDULE_DOMAIN
#define CONFIG_PHY_SCHEDULE_DOMAIN MODEM_SCHEDULE_DOMAIN1_COREMASK 
#endif 

#ifndef CONFIG_PHY_SCHEDULE_DOMAIN_COREBEGIN
#define CONFIG_PHY_SCHEDULE_DOMAIN_COREBEGIN MODEM_SCHEDULE_DOMAIN1_COREBEGIN 
#endif 

#ifndef CONFIG_PHY_SCHEDULE_DOMAIN_CORENUM
#define CONFIG_PHY_SCHEDULE_DOMAIN_CORENUM MODEM_SCHEDULE_DOMAIN1_CORENUM 
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

#ifndef MODEM_LTO
#define MODEM_LTO FEATURE_ON 
#endif 

#ifndef STACK_CANARY_COMPILE
#define STACK_CANARY_COMPILE 
#endif 

#ifndef ASAN_NO_DRV
#endif 

#ifndef CONFIG_NVIM
#define CONFIG_NVIM 
#endif 

#ifndef FEATURE_NV_SEC_ON
#define FEATURE_NV_SEC_ON 
#endif 

#ifndef CONFIG_NV_FUSION
#define CONFIG_NV_FUSION 
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

#ifndef ENABLE_BUILD_SOCP
#define ENABLE_BUILD_SOCP 
#endif 

#ifndef SOCP_V300
#define SOCP_V300 
#endif 

#ifndef ENABLE_BUILD_PRINT
#define ENABLE_BUILD_PRINT 
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

#ifndef CONFIG_MODULE_RRT
#define CONFIG_MODULE_RRT 
#endif 

#ifndef CONFIG_BUS_ERR_LR
#define CONFIG_BUS_ERR_LR 
#endif 

#ifndef CONFIG_NOC
#define CONFIG_NOC 
#endif 

#ifndef CONFIG_PDLOCK_RENEW
#define CONFIG_PDLOCK_RENEW 
#endif 

#ifndef CONFIG_MID
#define CONFIG_MID 
#endif 

#ifndef ENABLE_AMON_MDM
#define ENABLE_AMON_MDM 
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

#ifndef FEATURE_SCI_PROTOL_T1
#define FEATURE_SCI_PROTOL_T1 FEATURE_OFF 
#endif 

#ifndef FEATURE_SCI_ESIM
#define FEATURE_SCI_ESIM FEATURE_OFF 
#endif 

#ifndef CONFIG_SCI
#define CONFIG_SCI 
#endif 

#ifndef CONFIG_OCD
#define CONFIG_OCD 
#endif 

#ifndef CONFIG_CCORE_WDT
#define CONFIG_CCORE_WDT 
#endif 

#ifndef FEATURE_CHR_OM
#define FEATURE_CHR_OM FEATURE_OFF 
#endif 

#ifndef CONFIG_GPIO_PL061
#define CONFIG_GPIO_PL061 
#endif 

#ifndef CONFIG_ONOFF
#define CONFIG_ONOFF 
#endif 

#ifndef CONFIG_MLOADER
#define CONFIG_MLOADER 
#endif 

#ifndef CONFIG_RTC_ON_SOC
#endif 

#ifndef CONFIG_MODEM_RTC_ON_SOC
#endif 

#ifndef CONFIG_RTC_BUILD_CTRL
#endif 

#ifndef CONFIG_RTC_ON_PMU
#endif 

#ifndef CONFIG_PMU_RTC_SPMI
#endif 

#ifndef CONFIG_MLOADER_SEG_HEAD
#define CONFIG_MLOADER_SEG_HEAD 
#endif 

#ifndef FEATURE_ANTEN_DETECT
#define FEATURE_ANTEN_DETECT 
#endif 

#ifndef CONFIG_ANTEN
#define CONFIG_ANTEN 
#endif 

#ifndef CONFIG_RFILE_ON
#define CONFIG_RFILE_ON 
#endif 

#ifndef CONFIG_RTC_ON_SOC
#endif 

#ifndef CONFIG_RTC_ON_PMU
#define CONFIG_RTC_ON_PMU 
#endif 

#ifndef CONFIG_RTC_SET_TIME
#endif 

#ifndef CONFIG_ADC
#endif 

#ifndef CONFIG_HIFI_FUSION
#define CONFIG_HIFI_FUSION 
#endif 

#ifndef CONFIG_EFUSE
#endif 

#ifndef CONFIG_SYSBOOT_PARA
#define CONFIG_SYSBOOT_PARA 
#endif 

#ifndef CONFIG_SYSBOOT_PARA_DEBUG
#define CONFIG_SYSBOOT_PARA_DEBUG 
#endif 

#ifndef DTS_STATIC_MEM_SIZE
#define DTS_STATIC_MEM_SIZE 204800 
#endif 

#ifndef CONFIG_BALONG_CHIP_VERSION
#define CONFIG_BALONG_CHIP_VERSION cs 
#endif 

#ifndef CONFIG_OF
#define CONFIG_OF 
#endif 

#ifndef CONFIG_TIMER_COMM
#define CONFIG_TIMER_COMM 
#endif 

#ifndef CONFIG_TIMER_LITE
#endif 

#ifndef CONFIG_USE_TIMER_STAMP
#define CONFIG_USE_TIMER_STAMP 
#endif 

#ifndef CONFIG_MODULE_TIMER
#define CONFIG_MODULE_TIMER 
#endif 

#ifndef CONFIG_RING_BUF
#define CONFIG_RING_BUF 
#endif 

#ifndef CONFIG_TSP_HWLOCK
#define CONFIG_TSP_HWLOCK 
#endif 

#ifndef CONFIG_BALONG_EDMA
#define CONFIG_BALONG_EDMA 
#endif 

#ifndef CONFIG_EDMA_DEBUG
#define CONFIG_EDMA_DEBUG 
#endif 

#ifndef EDMA_ALL
#define EDMA_ALL 
#endif 

#ifndef CONFIG_HWADP
#define CONFIG_HWADP 
#endif 

#ifndef CONFIG_HWADP_V200
#define CONFIG_HWADP_V200 
#endif 

#ifndef CONFIG_SHARED_MEMORY
#define CONFIG_SHARED_MEMORY 
#endif 

#ifndef CONFIG_NMI
#define CONFIG_NMI 
#endif 

#ifndef CONFIG_BALONG_L2CACHE
#define CONFIG_BALONG_L2CACHE 
#endif 

#ifndef CONFIG_DEBUG_FTRACE
#endif 

#ifndef CONFIG_MPERF_PMU
#define CONFIG_MPERF_PMU 
#endif 

#ifndef CONFIG_MEMORY_LAYOUT
#define CONFIG_MEMORY_LAYOUT 
#endif 

#ifndef CONFIG_HITSP_VERIFY
#define CONFIG_HITSP_VERIFY 
#endif 

#ifndef CONFIG_BALONG_MODEM_RESET
#define CONFIG_BALONG_MODEM_RESET 
#endif 

#ifndef CONFIG_MODEM_RESET_FUSION
#define CONFIG_MODEM_RESET_FUSION 
#endif 

#ifndef CONFIG_MODEM_RESET_MBB
#define CONFIG_MODEM_RESET_MBB 
#endif 

#ifndef CONFIG_NEW_PLATFORM
#define CONFIG_NEW_PLATFORM 
#endif 

#ifndef CONFIG_IPF_VESION
#define CONFIG_IPF_VESION 2 
#endif 

#ifndef CONFIG_IPF_ADQ_LEN
#define CONFIG_IPF_ADQ_LEN 3 
#endif 

#ifndef CONFIG_EIPF_V2
#define CONFIG_EIPF_V2 
#endif 

#ifndef CONFIG_IPF_PROPERTY_MBB
#define CONFIG_IPF_PROPERTY_MBB 
#endif 

#ifndef CONFIG_L2DLE
#define CONFIG_L2DLE 
#endif 

#ifndef CONFIG_L2DLE_NO_MAA
#endif 

#ifndef CONFIG_L2DLE_SW_RLS
#endif 

#ifndef CONFIG_ECIPHER
#define CONFIG_ECIPHER 
#endif 

#ifndef CONFIG_ECIPHER_TSP
#define CONFIG_ECIPHER_TSP 
#endif 

#ifndef CONFIG_ULCIPHER
#define CONFIG_ULCIPHER 
#endif 

#ifndef CONFIG_ULCIPHER_V300
#define CONFIG_ULCIPHER_V300 
#endif 

#ifndef CONFIG_ULCIPHER_V310
#define CONFIG_ULCIPHER_V310 
#endif 

#ifndef CONFIG_BALONG_BBP_STU
#define CONFIG_BALONG_BBP_STU 
#endif 

#ifndef CONFIG_BALONG_TRANS_REPORT
#define CONFIG_BALONG_TRANS_REPORT 
#endif 

#ifndef CONFIG_TRANS_REPORT_TSP
#define CONFIG_TRANS_REPORT_TSP 
#endif 

#ifndef CONFIG_MAA_BALONG
#define CONFIG_MAA_BALONG 
#endif 

#ifndef CONFIG_MAA_V3
#define CONFIG_MAA_V3 
#endif 

#ifndef CONFIG_MAA_TSP
#define CONFIG_MAA_TSP 
#endif 

#ifndef CONFIG_ESPE
#define CONFIG_ESPE 
#endif 

#ifndef CONFIG_BALONG_ESPE
#define CONFIG_BALONG_ESPE 
#endif 

#ifndef SPEV300_SUPPORT
#define SPEV300_SUPPORT 
#endif 

#ifndef CONFIG_VCOM
#define CONFIG_VCOM 
#endif 

#ifndef CONFIG_VDEV
#define CONFIG_VDEV 
#endif 

#ifndef CONFIG_VDEV_PHONE
#endif 

#ifndef CONFIG_UART_ESL
#endif 

#ifndef CONFIG_UART_RTT
#endif 

#ifndef CONFIG_UART_SHELL
#define CONFIG_UART_SHELL 
#endif 

#ifndef CONFIG_OS_INCLUDE_SHELL
#define CONFIG_OS_INCLUDE_SHELL 
#endif 

#ifndef CONFIG_SHELL_SYMBOL_REG
#endif 

#ifndef CONFIG_DRV_SYM_HIDDEN
#endif 

#ifndef CONFIG_MODULE_IPC
#define CONFIG_MODULE_IPC 
#endif 

#ifndef CONFIG_EICC_V200
#define CONFIG_EICC_V200 
#endif 

#ifndef CONFIG_BALONG_MSG
#define CONFIG_BALONG_MSG 
#endif 

#ifndef CONFIG_CPUFREQ
#endif 

#ifndef CONFIG_SYSCTRL
#define CONFIG_SYSCTRL 
#endif 

#ifndef CONFIG_PMU_VERSION
#define CONFIG_PMU_VERSION pmu_v200 
#endif 

#ifndef CONFIG_BALONG_CCLK_GATE
#endif 

#ifndef CONFIG_BALONG_CCLK
#define CONFIG_BALONG_CCLK 
#endif 

#ifndef CONFIG_BALONG_CCLK_DEBUG
#define CONFIG_BALONG_CCLK_DEBUG 
#endif 

#ifndef CONFIG_BALONG_CCLK_ATUOGATE
#define CONFIG_BALONG_CCLK_ATUOGATE 
#endif 

#ifndef CONFIG_CCORE_WSRC
#define CONFIG_CCORE_WSRC 
#endif 

#ifndef CONFIG_CCORE_PM
#define CONFIG_CCORE_PM 
#endif 

#ifndef CONFIG_CCORE_SUSPEND
#endif 

#ifndef CONFIG_LLT_MDRV
#define CONFIG_LLT_MDRV 
#endif 

#ifndef CONFIG_HEATING_CALIBRATION
#define CONFIG_HEATING_CALIBRATION 
#endif 

#endif /*__PRODUCT_CONFIG_H__*/ 
