/* MD5: 26e8bc54ba69a846792d733907689a5e*/
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

#if !defined(__PRODUCT_CONFIG_DDR_H__)
#define __PRODUCT_CONFIG_DDR_H__

#ifndef TSP_PL2_MEM_ADDR
#define TSP_PL2_MEM_ADDR 0xF5000000 
#endif 

#ifndef TSP_PL2_MEM_SIZE
#define TSP_PL2_MEM_SIZE 0x600000 
#endif 

#ifndef TSP_PL2_MEM_HEAP_CACHE_SIZE
#define TSP_PL2_MEM_HEAP_CACHE_SIZE 0x5f800 
#endif 

#ifndef TSP_PL2_MEM_SPINLOCK_SIZE
#define TSP_PL2_MEM_SPINLOCK_SIZE 0x0 
#endif 

#ifndef TSP_PL2_MEM_UNCACHE_SIZE
#define TSP_PL2_MEM_UNCACHE_SIZE 0x31000 
#endif 

#ifndef TSP_PL2_MEM_UNCACHE_NOBAK_SIZE
#define TSP_PL2_MEM_UNCACHE_NOBAK_SIZE 0x28000 
#endif 

#ifndef TSP_PL1_MEM_ADDR
#define TSP_PL1_MEM_ADDR 0xF5F00000 
#endif 

#ifndef TSP_PL1_MEM_SIZE
#define TSP_PL1_MEM_SIZE 0x10000 
#endif 

#ifndef TSP_MPSCU_MP_REG_BASE
#define TSP_MPSCU_MP_REG_BASE 0xF5800000 
#endif 

#ifndef TSP_MPSCU_MP_REG_SIZE
#define TSP_MPSCU_MP_REG_SIZE 0x200000 
#endif 

#ifndef TSP_REGISTER_START_ADDR
#define TSP_REGISTER_START_ADDR 0xE0000000 
#endif 

#ifndef TSP_REGISTER_SIZE
#define TSP_REGISTER_SIZE 0x20000000 
#endif 

#ifndef TVP_PL2_MEM_ADDR
#define TVP_PL2_MEM_ADDR 0xe2b00000 
#endif 

#ifndef TVP_PL2_MEM_SIZE
#define TVP_PL2_MEM_SIZE 0x100000 
#endif 

#ifndef TVP_PL1_MEM_ADDR
#define TVP_PL1_MEM_ADDR 0xe2c00000 
#endif 

#ifndef TVP_PL1_MEM_SIZE
#define TVP_PL1_MEM_SIZE 0x80000 
#endif 

#ifndef TVP_MPSCU_MP_REG_BASE
#define TVP_MPSCU_MP_REG_BASE 0xe2600000 
#endif 

#ifndef TSP_L2M_MULTI_INST_VIRT_BASE_ADDR
#define TSP_L2M_MULTI_INST_VIRT_BASE_ADDR 0xc0000000 
#endif 

#ifndef TSP_L2M_MULTI_INST_VIRT_BASE_SIZE
#define TSP_L2M_MULTI_INST_VIRT_BASE_SIZE 0xc00000 
#endif 

#ifndef TSP_UART_ADDR
#define TSP_UART_ADDR 0xF4A26000 
#endif 

#ifndef TSP_UART_SIZE
#define TSP_UART_SIZE 0x2000 
#endif 

#ifndef TSP_GLOBAL_L1TCM_ADDR
#define TSP_GLOBAL_L1TCM_ADDR 0xF6000000 
#endif 

#ifndef TSP_GLOBAL_L1TCM_SIZE
#define TSP_GLOBAL_L1TCM_SIZE 0x90000 
#endif 

#ifndef TSP_LOCAL_L1TCM_ADDR
#define TSP_LOCAL_L1TCM_ADDR 0xF5F00000 
#endif 

#ifndef TSP_LOCAL_L1TCM_SIZE
#define TSP_LOCAL_L1TCM_SIZE 0x10000 
#endif 

#ifndef CCPU_LLRAM_BASE_ADDR
#define CCPU_LLRAM_BASE_ADDR 0xE0A00000 
#endif 

#ifndef CCPU_LLRAM_BASE_SIZE
#define CCPU_LLRAM_BASE_SIZE 0x100000 
#endif 

#ifndef CCPU_SRAM_SIZE
#define CCPU_SRAM_SIZE 0x2000 
#endif 

#ifndef CCPU_DFC_ADDR
#define CCPU_DFC_ADDR (CCPU_LLRAM_BASE_ADDR + CCPU_SRAM_SIZE) 
#endif 

#ifndef CCPU_DFC_SIZE
#define CCPU_DFC_SIZE 0x35800 
#endif 

#ifndef CONFIG_CCPU_HAS_LLRAM
#endif 

#ifndef CCPU_LLRAM_ADDR
#define CCPU_LLRAM_ADDR (CCPU_DFC_ADDR + CCPU_DFC_SIZE) 
#endif 

#ifndef CCPU_LLRAM_SIZE
#define CCPU_LLRAM_SIZE (CCPU_LLRAM_BASE_SIZE - CCPU_SRAM_SIZE - CCPU_DFC_SIZE) 
#endif 

#ifndef CONFIG_CCPU_HAS_TCM
#endif 

#ifndef CCPU_ITCM_ADDR
#define CCPU_ITCM_ADDR 0x0 
#endif 

#ifndef CCPU_ITCM_SIZE
#define CCPU_ITCM_SIZE 0x40000 
#endif 

#ifndef CCPU_ITCM_SIZE_CFG
#define CCPU_ITCM_SIZE_CFG (0x9u<<0x2) 
#endif 

#ifndef CCPU_DTCM_ADDR
#define CCPU_DTCM_ADDR (CCPU_ITCM_ADDR + CCPU_ITCM_SIZE) 
#endif 

#ifndef CCPU_DTCM_SIZE
#define CCPU_DTCM_SIZE 0x40000 
#endif 

#ifndef CCPU_DTCM_SIZE_CFG
#define CCPU_DTCM_SIZE_CFG (0x9u<<0x2) 
#endif 

#ifndef MEMMAP_PY
#define MEMMAP_PY 
#endif 

#ifndef HAC_TEXT_START_ADDR
#define HAC_TEXT_START_ADDR HAC_LLRAM_ADDR 
#endif 

#ifndef CONFIG_HAC_HAS_LLRAM
#endif 

#ifndef HAC_LLRAM_ADDR
#define HAC_LLRAM_ADDR 0xCF000000 
#endif 

#ifndef HAC_LLRAM_SIZE
#define HAC_LLRAM_SIZE 0x180000 
#endif 

#ifndef HAC_ITCM_ADDR
#define HAC_ITCM_ADDR 0x0 
#endif 

#ifndef HAC_ITCM_SIZE
#define HAC_ITCM_SIZE 0x40000 
#endif 

#ifndef HAC_ITCM_SIZE_CFG
#define HAC_ITCM_SIZE_CFG (0x9u<<0x2) 
#endif 

#ifndef HAC_DTCM_ADDR
#define HAC_DTCM_ADDR (CCPU_ITCM_ADDR + CCPU_ITCM_SIZE) 
#endif 

#ifndef HAC_DTCM_SIZE
#define HAC_DTCM_SIZE 0x40000 
#endif 

#ifndef HAC_DTCM_SIZE_CFG
#define HAC_DTCM_SIZE_CFG (0x9u<<0x2) 
#endif 

#ifndef HI_SRAM_MEM_ADDR
#define HI_SRAM_MEM_ADDR CCPU_LLRAM_BASE_ADDR 
#endif 

#ifndef HI_SRAM_SIZE
#define HI_SRAM_SIZE 0x2000 
#endif 

#ifndef DRV_SRAM_ADDR
#define DRV_SRAM_ADDR (HI_SRAM_MEM_ADDR) 
#endif 

#ifndef DRV_SRAM_SIZE
#define DRV_SRAM_SIZE 0x10000 
#endif 

#ifndef CPHY_SRAM_ADDR
#define CPHY_SRAM_ADDR ((DRV_SRAM_ADDR) + (DRV_SRAM_SIZE)) 
#endif 

#ifndef CPHY_SRAM_SIZE
#define CPHY_SRAM_SIZE 0xA0 
#endif 

#ifndef CPHY_LPC_SRAM_ADDR
#define CPHY_LPC_SRAM_ADDR ( CPHY_SRAM_ADDR ) 
#endif 

#ifndef CPHY_LPC_SRAM_SIZE
#define CPHY_LPC_SRAM_SIZE 0x20 
#endif 

#ifndef CPHY_1X_DATA_MBX_SRAM_ADDR
#define CPHY_1X_DATA_MBX_SRAM_ADDR ( (CPHY_LPC_SRAM_ADDR) + (CPHY_LPC_SRAM_SIZE) ) 
#endif 

#ifndef CPHY_1X_DATA_MBX_SRAM_SIZE
#define CPHY_1X_DATA_MBX_SRAM_SIZE 0x20 
#endif 

#ifndef CPHY_HRPD_DATA_MBX_SRAM_ADDR
#define CPHY_HRPD_DATA_MBX_SRAM_ADDR ( (CPHY_1X_DATA_MBX_SRAM_ADDR) + (CPHY_1X_DATA_MBX_SRAM_SIZE) ) 
#endif 

#ifndef CPHY_HRPD_DATA_MBX_SRAM_SIZE
#define CPHY_HRPD_DATA_MBX_SRAM_SIZE 0x3C 
#endif 

#ifndef DDR_MEM_ADDR
#define DDR_MEM_ADDR 0x00000000 
#endif 

#ifndef DDR_MEM_SIZE
#define DDR_MEM_SIZE 0x40000000 
#endif 

#ifndef DDR_APP_ACP_ADDR
#define DDR_APP_ACP_ADDR 0 
#endif 

#ifndef DDR_APP_ACP_SIZE
#define DDR_APP_ACP_SIZE 0 
#endif 

#ifndef DDR_MDM_ACP_ADDR
#define DDR_MDM_ACP_ADDR 0 
#endif 

#ifndef DDR_MDM_ACP_SIZE
#define DDR_MDM_ACP_SIZE 0 
#endif 

#ifndef DDR_HIBOOT_SIZE
#define DDR_HIBOOT_SIZE 0x400000 
#endif 

#ifndef DDR_FW_DTB_SIZE
#define DDR_FW_DTB_SIZE 0xC0000 
#endif 

#ifndef DDR_EARLY_LOG_SIZE
#define DDR_EARLY_LOG_SIZE 0x40000 
#endif 

#ifndef DDR_BL31_IMAGE_SIZE
#define DDR_BL31_IMAGE_SIZE 0x200000 
#endif 

#ifndef DDR_SECURE_OS_SIZE
#define DDR_SECURE_OS_SIZE 0xC00000 
#endif 

#ifndef DDR_MNTN_SIZE
#define DDR_MNTN_SIZE 0x400000 
#endif 

#ifndef DDR_MCORE_DTS_SIZE
#define DDR_MCORE_DTS_SIZE 0x100000 
#endif 

#ifndef DDR_MCORE_SIZE
#define DDR_MCORE_SIZE 0x9a00000 
#endif 

#ifndef DDR_RESERVED_SIZE
#define DDR_RESERVED_SIZE 0x2FC0000 
#endif 

#ifndef DDR_SDR_SIZE
#define DDR_SDR_SIZE 0x1C0000 
#endif 

#ifndef DDR_PDE_IMAGE_SIZE
#define DDR_PDE_IMAGE_SIZE 0x600000 
#endif 

#ifndef DDR_HIFI_SIZE
#define DDR_HIFI_SIZE 0x800000 
#endif 

#ifndef DDR_RFIC_SUB6G_IMAGE_SIZE
#define DDR_RFIC_SUB6G_IMAGE_SIZE 0x240000 
#endif 

#ifndef DDR_RFIC_HF_IMAGE_SIZE
#define DDR_RFIC_HF_IMAGE_SIZE 0x100000 
#endif 

#ifndef DDR_RFIC_IMAGE_SIZE
#define DDR_RFIC_IMAGE_SIZE 0x340000 
#endif 

#ifndef DDR_SHARED_NSRO_SIZE
#define DDR_SHARED_NSRO_SIZE 0xE00000 
#endif 

#ifndef DDR_SHARED_UNSEC_SIZE
#define DDR_SHARED_UNSEC_SIZE 0x1C0000 
#endif 

#ifndef DDR_SHARED_SEC_SIZE
#define DDR_SHARED_SEC_SIZE 0x80000 
#endif 

#ifndef DDR_MCU_SIZE
#define DDR_MCU_SIZE 0x100000 
#endif 

#ifndef DDR_ACORE_SIZE
#define DDR_ACORE_SIZE 0xF600000 
#endif 

#ifndef DDR_HIBOOT_RESERVE_SIZE
#define DDR_HIBOOT_RESERVE_SIZE 0x1400000 
#endif 

#ifndef DDR_ACORE_DTS_SIZE
#define DDR_ACORE_DTS_SIZE 0x100000 
#endif 

#ifndef DDR_SOCP_SIZE
#define DDR_SOCP_SIZE 0x4000000 
#endif 

#ifndef DDR_FULLSTACK_MEM_SIZE
#define DDR_FULLSTACK_MEM_SIZE 0x0 
#endif 

#ifndef DDR_LPMCU_IMAGE_SIZE
#define DDR_LPMCU_IMAGE_SIZE 0x40000 
#endif 

#ifndef DDR_MTD_MEM_SIZE
#define DDR_MTD_MEM_SIZE 0x0 
#endif 

#ifndef DDR_SHARED_MEM_SIZE
#define DDR_SHARED_MEM_SIZE ((DDR_SHARED_NSRO_SIZE) - 0x1000) 
#endif 

#ifndef SOCP_RTT_REG_SIZE
#define SOCP_RTT_REG_SIZE 0x2000 
#endif 

#ifndef DIAG_RTT_DL_BUF_SIZE
#define DIAG_RTT_DL_BUF_SIZE 0xe000 
#endif 

#ifndef DIAG_RTT_CNF_BUF_SIZE
#define DIAG_RTT_CNF_BUF_SIZE 0x10000 
#endif 

#ifndef DIAG_RTT_PHY_IND_BUF_SIZE
#define DIAG_RTT_PHY_IND_BUF_SIZE 0x100000 
#endif 

#ifndef BBPDS_BUS_BUF_SIZE
#define BBPDS_BUS_BUF_SIZE 0x10000 
#endif 

#ifndef HIFI_LOAD_BUF_SIZE
#define HIFI_LOAD_BUF_SIZE 0x800000 
#endif 

#ifndef NPHY_HARQ_BUF_SIZE
#define NPHY_HARQ_BUF_SIZE 0x2000000 
#endif 

#ifndef DDR_MCORE_UNCACHE_SIZE
#define DDR_MCORE_UNCACHE_SIZE 0xA00000 
#endif 

#ifndef DDR_HIBOOT_CACHE_SIZE
#define DDR_HIBOOT_CACHE_SIZE 0x300000 
#endif 

#ifndef DDR_HIBOOT_UNCACHE_SIZE
#define DDR_HIBOOT_UNCACHE_SIZE 0x100000 
#endif 

#ifndef DDR_HIBOOT_CACHE_ADDR
#define DDR_HIBOOT_CACHE_ADDR ((DDR_MEM_ADDR)) 
#endif 

#ifndef DDR_HIBOOT_UNCACHE_ADDR
#define DDR_HIBOOT_UNCACHE_ADDR ((DDR_HIBOOT_CACHE_ADDR)+(DDR_HIBOOT_CACHE_SIZE)) 
#endif 

#ifndef DDR_HIBOOT_ADDR
#define DDR_HIBOOT_ADDR ((DDR_MEM_ADDR)) 
#endif 

#ifndef DDR_FW_DTB_ADDR
#define DDR_FW_DTB_ADDR ((DDR_HIBOOT_ADDR)+(DDR_HIBOOT_SIZE)) 
#endif 

#ifndef DDR_EARLY_LOG_ADDR
#define DDR_EARLY_LOG_ADDR ((DDR_FW_DTB_ADDR)+(DDR_FW_DTB_SIZE)) 
#endif 

#ifndef DDR_BL31_IMAGE_ADDR
#define DDR_BL31_IMAGE_ADDR ((DDR_EARLY_LOG_ADDR)+(DDR_EARLY_LOG_SIZE)) 
#endif 

#ifndef DDR_MNTN_ADDR
#define DDR_MNTN_ADDR ((DDR_BL31_IMAGE_ADDR)+(DDR_BL31_IMAGE_SIZE)) 
#endif 

#ifndef DDR_MCORE_DTS_ADDR
#define DDR_MCORE_DTS_ADDR ((DDR_MNTN_ADDR)+(DDR_MNTN_SIZE)) 
#endif 

#ifndef DDR_SECURE_OS_ADDR
#define DDR_SECURE_OS_ADDR ((DDR_MCORE_DTS_ADDR)+(DDR_MCORE_DTS_SIZE)) 
#endif 

#ifndef DDR_MCORE_ADDR
#define DDR_MCORE_ADDR ((DDR_SECURE_OS_ADDR)+(DDR_SECURE_OS_SIZE)) 
#endif 

#ifndef DDR_RESERVED_ADDR
#define DDR_RESERVED_ADDR ((DDR_MCORE_ADDR)+(DDR_MCORE_SIZE)) 
#endif 

#ifndef DDR_SDR_ADDR
#define DDR_SDR_ADDR ((DDR_RESERVED_ADDR)+(DDR_RESERVED_SIZE)) 
#endif 

#ifndef DDR_PDE_IMAGE_ADDR
#define DDR_PDE_IMAGE_ADDR ((DDR_SDR_ADDR)+(DDR_SDR_SIZE)) 
#endif 

#ifndef DDR_HIFI_ADDR
#define DDR_HIFI_ADDR ((DDR_PDE_IMAGE_ADDR)+(DDR_PDE_IMAGE_SIZE)) 
#endif 

#ifndef DDR_RFIC_IMAGE_ADDR
#define DDR_RFIC_IMAGE_ADDR ((DDR_HIFI_ADDR)+(DDR_HIFI_SIZE)) 
#endif 

#ifndef DDR_RFIC_SUB6G_IMAGE_ADDR
#define DDR_RFIC_SUB6G_IMAGE_ADDR ((DDR_HIFI_ADDR)+(DDR_HIFI_SIZE)) 
#endif 

#ifndef DDR_RFIC_HF_IMAGE_ADDR
#define DDR_RFIC_HF_IMAGE_ADDR ((DDR_RFIC_SUB6G_IMAGE_ADDR)+(DDR_RFIC_SUB6G_IMAGE_SIZE)) 
#endif 

#ifndef DDR_SHARED_NSRO_ADDR
#define DDR_SHARED_NSRO_ADDR ((DDR_RFIC_HF_IMAGE_ADDR)+(DDR_RFIC_HF_IMAGE_SIZE)) 
#endif 

#ifndef DDR_SHARED_UNSEC_ADDR
#define DDR_SHARED_UNSEC_ADDR ((DDR_SHARED_NSRO_ADDR)+(DDR_SHARED_NSRO_SIZE)) 
#endif 

#ifndef DDR_SHARED_SEC_ADDR
#define DDR_SHARED_SEC_ADDR ((DDR_SHARED_UNSEC_ADDR)+(DDR_SHARED_UNSEC_SIZE)) 
#endif 

#ifndef DDR_MCU_ADDR
#define DDR_MCU_ADDR ((DDR_SHARED_SEC_ADDR)+(DDR_SHARED_SEC_SIZE)) 
#endif 

#ifndef DDR_ACORE_ADDR
#define DDR_ACORE_ADDR ((DDR_MCU_ADDR)+(DDR_MCU_SIZE)) 
#endif 

#ifndef DDR_HIBOOT_RESERVE_ADDR
#define DDR_HIBOOT_RESERVE_ADDR ((DDR_ACORE_ADDR)+(DDR_ACORE_SIZE)-(DDR_HIBOOT_RESERVE_SIZE)) 
#endif 

#ifndef DDR_MNTN_RESERVE_ADDR
#define DDR_MNTN_RESERVE_ADDR ((DDR_HIBOOT_RESERVE_ADDR)-(DDR_MNTN_SIZE)) 
#endif 

#ifndef DDR_ACORE_DTS_ADDR
#define DDR_ACORE_DTS_ADDR ((DDR_ACORE_ADDR)+(DDR_ACORE_SIZE)) 
#endif 

#ifndef DDR_SOCP_ADDR
#define DDR_SOCP_ADDR 0x20000000 
#endif 

#ifndef DDR_SHARED_MEM_ADDR
#define DDR_SHARED_MEM_ADDR ((DDR_SHARED_NSRO_ADDR) + 0x1000) 
#endif 

#ifndef DDR_MTD_MEM_ADDR
#define DDR_MTD_MEM_ADDR 0 
#endif 

#ifndef DDR_FULLSTACK_MEM_ADDR
#define DDR_FULLSTACK_MEM_ADDR 0 
#endif 

#ifndef DDR_LPMCU_IMAGE_ADDR
#define DDR_LPMCU_IMAGE_ADDR ((DDR_SOCP_ADDR)+(DDR_SOCP_SIZE)) 
#endif 

#ifndef SOCP_RTT_REG_ADDR
#define SOCP_RTT_REG_ADDR ((DDR_LPMCU_IMAGE_ADDR)+(DDR_LPMCU_IMAGE_SIZE)) 
#endif 

#ifndef DIAG_RTT_DL_BUF_ADDR
#define DIAG_RTT_DL_BUF_ADDR ((SOCP_RTT_REG_ADDR)+(SOCP_RTT_REG_SIZE)) 
#endif 

#ifndef DIAG_RTT_CNF_BUF_ADDR
#define DIAG_RTT_CNF_BUF_ADDR ((DIAG_RTT_DL_BUF_ADDR)+(DIAG_RTT_DL_BUF_SIZE)) 
#endif 

#ifndef DIAG_RTT_PHY_IND_BUF_ADDR
#define DIAG_RTT_PHY_IND_BUF_ADDR ((DIAG_RTT_CNF_BUF_ADDR)+(DIAG_RTT_CNF_BUF_SIZE)) 
#endif 

#ifndef BBPDS_BUS_BUF_ADDR
#define BBPDS_BUS_BUF_ADDR ((DIAG_RTT_PHY_IND_BUF_ADDR)+(DIAG_RTT_PHY_IND_BUF_SIZE)) 
#endif 

#ifndef HIFI_LOAD_BUF_ADDR
#define HIFI_LOAD_BUF_ADDR ((BBPDS_BUS_BUF_ADDR)+(BBPDS_BUS_BUF_SIZE)) 
#endif 

#ifndef NPHY_HARQ_BUF_ADDR
#define NPHY_HARQ_BUF_ADDR ((HIFI_LOAD_BUF_ADDR)+(HIFI_LOAD_BUF_SIZE)) 
#endif 

#ifndef DDR_LRCCPU_DTS_SIZE
#define DDR_LRCCPU_DTS_SIZE 0x80000 
#endif 

#ifndef DDR_LPMCU_DTS_SIZE
#define DDR_LPMCU_DTS_SIZE 0x80000 
#endif 

#ifndef DDR_NRCCPU_DTS_SIZE
#define DDR_NRCCPU_DTS_SIZE 0 
#endif 

#ifndef DDR_L2CPU_DTS_SIZE
#define DDR_L2CPU_DTS_SIZE 0 
#endif 

#ifndef DDR_MDTS_TOTAL_SIZE
#define DDR_MDTS_TOTAL_SIZE ((DDR_LRCCPU_DTS_SIZE) + (DDR_LPMCU_DTS_SIZE) + (DDR_NRCCPU_DTS_SIZE) + (DDR_L2CPU_DTS_SIZE)) 
#endif 

#ifndef DDR_TSP_DTS_SIZE
#define DDR_TSP_DTS_SIZE ((DDR_LRCCPU_DTS_SIZE)) 
#endif 

#ifndef DDR_FW_DTS_SIZE
#define DDR_FW_DTS_SIZE ((DDR_LPMCU_DTS_SIZE)) 
#endif 

#ifndef DDR_LRCCPU_DTS_ADDR
#define DDR_LRCCPU_DTS_ADDR ((DDR_MCORE_DTS_ADDR)) 
#endif 

#ifndef DDR_LPMCU_DTS_ADDR
#define DDR_LPMCU_DTS_ADDR ((DDR_LRCCPU_DTS_ADDR) + (DDR_LRCCPU_DTS_SIZE)) 
#endif 

#ifndef DDR_NRCCPU_DTS_ADDR
#define DDR_NRCCPU_DTS_ADDR ((DDR_LPMCU_DTS_ADDR) + (DDR_LPMCU_DTS_SIZE)) 
#endif 

#ifndef DDR_L2CPU_DTS_ADDR
#define DDR_L2CPU_DTS_ADDR ((DDR_NRCCPU_DTS_ADDR) + (DDR_NRCCPU_DTS_SIZE)) 
#endif 

#ifndef DDR_TSP_DTS_ADDR
#define DDR_TSP_DTS_ADDR ((DDR_LRCCPU_DTS_ADDR)) 
#endif 

#ifndef DDR_FW_DTS_ADDR
#define DDR_FW_DTS_ADDR ((DDR_LPMCU_DTS_ADDR)) 
#endif 

#ifndef MEM_ADJUST_INTERCEPT
#define MEM_ADJUST_INTERCEPT 
#endif 

#ifndef MCORE_TEXT_START_ADDR
#define MCORE_TEXT_START_ADDR ((DDR_MCORE_ADDR)) 
#endif 

#ifndef HIBOOT_DDR_ENTRY
#define HIBOOT_DDR_ENTRY ((DDR_HIBOOT_ADDR)) 
#endif 

#ifndef PRODUCT_CFG_KERNEL_ENTRY
#define PRODUCT_CFG_KERNEL_ENTRY ((DDR_ACORE_ADDR)+0x80000-0x8000) 
#endif 

#ifndef PRODUCT_KERNEL_PARAMS_PHYS
#define PRODUCT_KERNEL_PARAMS_PHYS ((DDR_ACORE_ADDR)+0x100) 
#endif 

#ifndef ONCHIP_HIBOOT_ADDR
#define ONCHIP_HIBOOT_ADDR ((MCORE_TEXT_START_ADDR)+0x100000-0x1000) 
#endif 

#ifndef DDR_MCORE_UNCACHE_ADDR
#define DDR_MCORE_UNCACHE_ADDR ( (DDR_MCORE_ADDR   ) + (DDR_MCORE_SIZE) - (DDR_MCORE_UNCACHE_SIZE)) 
#endif 

#ifndef DDR_SDR_UNCACHE_ADDR
#define DDR_SDR_UNCACHE_ADDR ( (DDR_SDR_ADDR   ) + (DDR_SDR_SIZE) - (DDR_SDR_UNCACHE_SIZE)) 
#endif 

#ifndef MDM_SANTIZIER_MEM_SIZE
#define MDM_SANTIZIER_MEM_SIZE 0x02000000 
#endif 

#ifndef MDM_SANTIZIER_MEM_ADDR
#define MDM_SANTIZIER_MEM_ADDR 0x30000000 
#endif 

#ifndef MODEM_SANITIZER_ADDR_OFFSET
#define MODEM_SANITIZER_ADDR_OFFSET 0x30000000 
#endif 

#ifndef DDR_SHA_NV_SIZE
#define DDR_SHA_NV_SIZE 0xB00000 
#endif 

#ifndef DDR_HIFI_MBX_ADDR
#define DDR_HIFI_MBX_ADDR ((DDR_SHARED_UNSEC_ADDR) + (DDR_SHA_NV_SIZE)) 
#endif 

#ifndef DDR_HIFI_MBX_SIZE
#define DDR_HIFI_MBX_SIZE (0X9800) 
#endif 

#ifndef NV_MBN_MAX_SIZE
#define NV_MBN_MAX_SIZE 0x20000 
#endif 

#ifndef NV_DDR_SIZE
#define NV_DDR_SIZE (DDR_SHA_NV_SIZE) 
#endif 

#ifndef NV_COMM_BIN_FILE_MAX_SIZE
#define NV_COMM_BIN_FILE_MAX_SIZE 0xA08C00 
#endif 

#ifndef SHM_SIZE_HIFI_MBX
#define SHM_SIZE_HIFI_MBX (DDR_HIFI_MBX_SIZE) 
#endif 

#ifndef SHM_SIZE_HIFI
#define SHM_SIZE_HIFI (10*1024) 
#endif 

#ifndef SHM_SIZE_TLPHY
#define SHM_SIZE_TLPHY (12*1024) 
#endif 

#ifndef SHM_SIZE_TEMPERATURE
#define SHM_SIZE_TEMPERATURE (3*1024) 
#endif 

#ifndef SHM_SIZE_DDM_LOAD
#define SHM_SIZE_DDM_LOAD (1*1024) 
#endif 

#ifndef SHM_SIZE_MEM_APPA9_PM_BOOT
#define SHM_SIZE_MEM_APPA9_PM_BOOT (0x10000) 
#endif 

#ifndef SHM_SIZE_MEM_MDMA9_PM_BOOT
#define SHM_SIZE_MEM_MDMA9_PM_BOOT (0x2000) 
#endif 

#ifndef SHM_SIZE_TENCILICA_MULT_BAND
#define SHM_SIZE_TENCILICA_MULT_BAND (0x8000) 
#endif 

#ifndef SHM_SIZE_ICC
#define SHM_SIZE_ICC (0x61800) 
#endif 

#ifndef SHM_SIZE_IPF
#define SHM_SIZE_IPF (0x10000) 
#endif 

#ifndef SHM_SIZE_PSAM
#define SHM_SIZE_PSAM (0) 
#endif 

#ifndef SHM_SIZE_WAN
#define SHM_SIZE_WAN (0x8000) 
#endif 

#ifndef SHM_SIZE_NV
#define SHM_SIZE_NV (NV_DDR_SIZE) 
#endif 

#ifndef SHM_SIZE_M3_MNTN
#define SHM_SIZE_M3_MNTN (0x20000) 
#endif 

#ifndef SHM_SIZE_TIMESTAMP
#define SHM_SIZE_TIMESTAMP (1*1024) 
#endif 

#ifndef SHM_SIZE_IOS
#define SHM_SIZE_IOS (6*1024) 
#endif 

#ifndef SHM_SIZE_RESTORE_AXI
#define SHM_SIZE_RESTORE_AXI (96*1024) 
#endif 

#ifndef SHM_SIZE_PMU
#define SHM_SIZE_PMU (3*1024) 
#endif 

#ifndef SHM_SIZE_PTABLE
#define SHM_SIZE_PTABLE (2*1024) 
#endif 

#ifndef SHM_SIZE_CCORE_RESET
#define SHM_SIZE_CCORE_RESET (0x400) 
#endif 

#ifndef SHM_SIZE_PM_OM
#define SHM_SIZE_PM_OM (256*1024) 
#endif 

#ifndef SHM_SIZE_M3PM
#define SHM_SIZE_M3PM (0x1000) 
#endif 

#ifndef SHM_SIZE_SLICE_MEM
#define SHM_SIZE_SLICE_MEM (0x1000) 
#endif 

#ifndef SHM_SIZE_OSA_LOG
#define SHM_SIZE_OSA_LOG (1024) 
#endif 

#ifndef SHM_SIZE_WAS_LOG
#define SHM_SIZE_WAS_LOG (1024) 
#endif 

#ifndef SHM_SIZE_SRAM_BAK
#define SHM_SIZE_SRAM_BAK (HI_SRAM_SIZE) 
#endif 

#ifndef SHM_SIZE_SRAM_TO_DDR
#define SHM_SIZE_SRAM_TO_DDR (HI_SRAM_SIZE) 
#endif 

#ifndef SHM_SIZE_M3RSRACC_BD
#define SHM_SIZE_M3RSRACC_BD (1024) 
#endif 

#ifndef SHM_SIZE_AXI_MEM
#define SHM_SIZE_AXI_MEM (0x40000) 
#endif 

#ifndef SHM_SIZE_LLRAM_PM
#define SHM_SIZE_LLRAM_PM (0x50000) 
#endif 

#ifndef SHM_SIZE_SIM_MEMORY
#define SHM_SIZE_SIM_MEMORY (256*1024) 
#endif 

#ifndef SHM_SIZE_PRODUCT_MEM
#define SHM_SIZE_PRODUCT_MEM (2*1024) 
#endif 

#ifndef CONFIG_TVPCCPU_HAS_LLRAM
#endif 

#ifndef TVPCCPU_LLRAM_BASE_ADDR
#define TVPCCPU_LLRAM_BASE_ADDR 0xE2800000 
#endif 

#ifndef TVPCCPU_LLRAM_BASE_SIZE
#define TVPCCPU_LLRAM_BASE_SIZE 0x20000 
#endif 

#ifndef TVPCCPU_SRAM_SIZE
#define TVPCCPU_SRAM_SIZE 0x3000 
#endif 

#ifndef TVPCCPU_LLRAM_ADDR
#define TVPCCPU_LLRAM_ADDR (TVPCCPU_LLRAM_BASE_ADDR + TVPCCPU_SRAM_SIZE) 
#endif 

#ifndef TVPCCPU_LLRAM_SIZE
#define TVPCCPU_LLRAM_SIZE (TVPCCPU_LLRAM_BASE_SIZE - TVPCCPU_SRAM_SIZE) 
#endif 

#ifndef CONFIG_TVPCCPU_HAS_TCM
#endif 

#ifndef CONFIG_TSPCCPU_HAS_LLRAM
#endif 

#ifndef TSPCCPU_LLRAM_BASE_ADDR
#define TSPCCPU_LLRAM_BASE_ADDR 0xE0000000 
#endif 

#ifndef TSPCCPU_LLRAM_BASE_SIZE
#define TSPCCPU_LLRAM_BASE_SIZE 0xc0000 
#endif 

#ifndef TSPCCPU_SRAM_SIZE
#define TSPCCPU_SRAM_SIZE 0x3000 
#endif 

#ifndef TSPCCPU_LLRAM_ADDR
#define TSPCCPU_LLRAM_ADDR (TSPCCPU_LLRAM_BASE_ADDR + TSPCCPU_SRAM_SIZE) 
#endif 

#ifndef TSPCCPU_LLRAM_SIZE
#define TSPCCPU_LLRAM_SIZE (TSPCCPU_LLRAM_BASE_SIZE - TSPCCPU_SRAM_SIZE) 
#endif 

#ifdef PLAT_TYPE_SLT 
#ifndef SLT_TSP_DDR_ADDR
#define SLT_TSP_DDR_ADDR ((DDR_MCORE_ADDR)) 
#endif 

#ifndef SLT_TSP_DDR_SIZE
#define SLT_TSP_DDR_SIZE 0x1600000 
#endif 

#ifndef SLT_TVP_DDR_ADDR
#define SLT_TVP_DDR_ADDR ((DDR_SDR_ADDR)) 
#endif 

#ifndef SLT_TVP_DDR_SIZE
#define SLT_TVP_DDR_SIZE 0x100000 
#endif 

#ifndef SLT_HIFI_DDR_ADDR
#define SLT_HIFI_DDR_ADDR ((DDR_HIFI_ADDR)) 
#endif 

#ifndef SLT_HIFI_DDR_SIZE
#define SLT_HIFI_DDR_SIZE 0x100000 
#endif 

#ifndef SLT_PDE_DDR_ADDR
#define SLT_PDE_DDR_ADDR ((DDR_PDE_IMAGE_ADDR)) 
#endif 

#ifndef SLT_PDE_DDR_SIZE
#define SLT_PDE_DDR_SIZE 0x200000 
#endif 

#endif
#endif /*__PRODUCT_CONFIG_H__*/ 
