/* MD5: ed67c67b3905c409d7b1642f160c52f2*/
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

#if !defined(__PRODUCT_CONFIG_DRV_TVP_H__)
#define __PRODUCT_CONFIG_DRV_TVP_H__

#ifndef ENABLE_BUILD_VARS
#define ENABLE_BUILD_VARS 
#endif 

#ifndef CCPU_OS
#define CCPU_OS RTOSCK_SMP 
#endif 

#ifndef CCPU_TVP_OS
#define CCPU_TVP_OS RTOSCK_TVP_V100 
#endif 

#ifndef CCPU_TSP_OS
#define CCPU_TSP_OS RTOSCK_TSP_V100 
#endif 

#ifndef HCC_VERSION
#define HCC_VERSION 7.3 
#endif 

#ifndef CONFIG_HAS_TVP_MODEM_DRIVER
#define CONFIG_HAS_TVP_MODEM_DRIVER 
#endif 

#ifndef CCPU_CORE_NUM
#define CCPU_CORE_NUM 1 
#endif 

#ifndef CCPU_RUN_COREMASK
#define CCPU_RUN_COREMASK 0x1 
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

#ifndef CONFIG_NVIM
#define CONFIG_NVIM 
#endif 

#ifndef FEATURE_NV_SEC_ON
#define FEATURE_NV_SEC_ON 
#endif 

#ifndef CONFIG_NV_COMM
#endif 

#ifndef CONFIG_NV_READ
#define CONFIG_NV_READ 
#endif 

#ifndef CONFIG_DIAG_SYSTEM
#define CONFIG_DIAG_SYSTEM 
#endif 

#ifndef DIAG_SYSTEM_5G
#define DIAG_SYSTEM_5G 
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

#ifdef EMU_TYPE_ESL 
#ifndef PLATFORM_VERSION_ESL
#define PLATFORM_VERSION_ESL 
#endif 

#endif
#ifndef CONFIG_ONOFF
#define CONFIG_ONOFF 
#endif 

#ifndef CONFIG_SYSCTRL
#define CONFIG_SYSCTRL 
#endif 

#ifndef CONFIG_UART_SHELL
#define CONFIG_UART_SHELL 
#endif 

#ifndef CONFIG_OS_INCLUDE_SHELL
#define CONFIG_OS_INCLUDE_SHELL 
#endif 

#ifndef CONFIG_SHELL_SYMBOL_REG
#define CONFIG_SHELL_SYMBOL_REG 
#endif 

#ifndef CONFIG_OF
#define CONFIG_OF 
#endif 

#ifndef CONFIG_TIMER_COMM
#endif 

#ifndef CONFIG_TIMER_LITE
#define CONFIG_TIMER_LITE 
#endif 

#ifndef CONFIG_USE_TIMER_STAMP
#define CONFIG_USE_TIMER_STAMP 
#endif 

#ifndef CONFIG_MODULE_TIMER
#define CONFIG_MODULE_TIMER 
#endif 

#ifndef CONFIG_BALONG_EDMA
#define CONFIG_BALONG_EDMA 
#endif 

#ifndef CONFIG_EDMA_DEBUG
#define CONFIG_EDMA_DEBUG 
#endif 

#ifndef CONFIG_EICC_V200
#define CONFIG_EICC_V200 
#endif 

#ifndef CONFIG_EICC_MINOR_V000
#define CONFIG_EICC_MINOR_V000 
#endif 

#endif /*__PRODUCT_CONFIG_H__*/ 
