/* MD5: d873b8845b8ccce3997cc72432c7aa94*/
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

#if !defined(__PRODUCT_CONFIG_NRPS_ES_H__)
#define __PRODUCT_CONFIG_NRPS_ES_H__

#ifndef FEATURE_MLOG
#define FEATURE_MLOG FEATURE_ON 
#endif 

#ifndef FEATURE_DT
#define FEATURE_DT FEATURE_ON 
#endif 

#ifndef FEATURE_NPHY_STUB_ESL
#define FEATURE_NPHY_STUB_ESL FEATURE_OFF 
#endif 

#ifndef FEATURE_NL2_MAA_ALLOC
#define FEATURE_NL2_MAA_ALLOC FEATURE_OFF 
#endif 

#ifndef NR_PROTOL_STACK_ENG
#define NR_PROTOL_STACK_ENG 
#endif 

#ifndef FEATURE_NSSAI_AUTH
#define FEATURE_NSSAI_AUTH FEATURE_ON 
#endif 

#ifndef FEATURE_OPRDEF_CATEGORY
#define FEATURE_OPRDEF_CATEGORY FEATURE_ON 
#endif 

#ifndef FEATURE_LADN
#define FEATURE_LADN FEATURE_ON 
#endif 

#ifndef NR_MAX_SERVING_CC_NUM
#define NR_MAX_SERVING_CC_NUM 4 
#endif 

#ifndef NR_MAX_UL_SERVING_CC_NUM
#define NR_MAX_UL_SERVING_CC_NUM 2 
#endif 

#ifndef NMAC_MAX_UL_ENTITY_NUM
#define NMAC_MAX_UL_ENTITY_NUM 4 
#endif 

#ifndef NMAC_MAX_CELL_ENTITY_NUM
#define NMAC_MAX_CELL_ENTITY_NUM 8 
#endif 

#ifndef NMAC_MAX_UL_CELL_NUM
#define NMAC_MAX_UL_CELL_NUM 4 
#endif 

#ifndef NMAC_MAX_UL_HARQ_PROC_NUM
#define NMAC_MAX_UL_HARQ_PROC_NUM 18 
#endif 

#ifndef NR_MAX_CG_NUM
#define NR_MAX_CG_NUM 2 
#endif 

#ifndef FEATURE_MODEM1_SUPPORT_NR
#define FEATURE_MODEM1_SUPPORT_NR FEATURE_OFF 
#endif 

#ifndef NR_MAX_PER_PLMN_NRSA_BC_NUM
#define NR_MAX_PER_PLMN_NRSA_BC_NUM 128 
#endif 

#ifndef NR_MAX_PER_PLMN_ENDC_BC_NUM
#define NR_MAX_PER_PLMN_ENDC_BC_NUM 512 
#endif 

#ifndef NR_MAX_PER_PLMN_NRDC_BC_NUM
#define NR_MAX_PER_PLMN_NRDC_BC_NUM 16 
#endif 

#ifndef NR_MAX_PER_PLMN_TXSW_NRSA_BC_NUM
#define NR_MAX_PER_PLMN_TXSW_NRSA_BC_NUM 64 
#endif 

#ifndef NR_MAX_PER_PLMN_TXSW_ENDC_BC_NUM
#define NR_MAX_PER_PLMN_TXSW_ENDC_BC_NUM 128 
#endif 

#ifndef NR_MAX_NRSA_BC_NUM
#define NR_MAX_NRSA_BC_NUM 512 
#endif 

#ifndef NR_MAX_ENDC_BC_NUM
#define NR_MAX_ENDC_BC_NUM 1024 
#endif 

#ifndef NR_MAX_NRDC_BC_NUM
#define NR_MAX_NRDC_BC_NUM 16 
#endif 

#ifndef NR_MAX_TXSW_NRSA_BC_NUM
#define NR_MAX_TXSW_NRSA_BC_NUM 64 
#endif 

#ifndef NR_MAX_TXSW_ENDC_BC_NUM
#define NR_MAX_TXSW_ENDC_BC_NUM 128 
#endif 

#ifndef NR_MAX_NR_FSD_OTHER_PARA_NUM
#define NR_MAX_NR_FSD_OTHER_PARA_NUM 128 
#endif 

#ifndef NR_MAX_NR_FSU_OTHER_PARA_NUM
#define NR_MAX_NR_FSU_OTHER_PARA_NUM 128 
#endif 

#ifndef NR_MAX_NR_FSD_PARA_NUM
#define NR_MAX_NR_FSD_PARA_NUM 256 
#endif 

#ifndef NR_MAX_NR_FSU_PARA_NUM
#define NR_MAX_NR_FSU_PARA_NUM 256 
#endif 

#ifndef NR_MAX_LTE_FSD_PARA_NUM
#define NR_MAX_LTE_FSD_PARA_NUM 256 
#endif 

#ifndef NR_MAX_LTE_FSU_PARA_NUM
#define NR_MAX_LTE_FSU_PARA_NUM 256 
#endif 

#ifndef NR_MAX_NR_FSPC_DL_NUM
#define NR_MAX_NR_FSPC_DL_NUM 128 
#endif 

#ifndef NR_MAX_NR_FSPC_UL_NUM
#define NR_MAX_NR_FSPC_UL_NUM 128 
#endif 

#ifndef NR_MAX_SIMPLE_FSC_NUM_PER_SUPER_FSC
#define NR_MAX_SIMPLE_FSC_NUM_PER_SUPER_FSC 16 
#endif 

#ifndef NR_MAX_FSC_NUM
#define NR_MAX_FSC_NUM 128 
#endif 

#ifndef NR_MAX_PER_BC_NR_BAND_NUM
#define NR_MAX_PER_BC_NR_BAND_NUM 2 
#endif 

#ifndef NR_MAX_PER_BC_LTE_BAND_NUM
#define NR_MAX_PER_BC_LTE_BAND_NUM 5 
#endif 

#ifndef NR_MAX_PER_BC_BAND_NUM
#define NR_MAX_PER_BC_BAND_NUM 6 
#endif 

#ifndef NR_MAX_PER_BAND_CC_NUM
#define NR_MAX_PER_BAND_CC_NUM 6 
#endif 

#ifndef NR_MAX_L2DLE_NRLC_ENTITY_NUM
#define NR_MAX_L2DLE_NRLC_ENTITY_NUM 16 
#endif 

#ifndef NR_MAX_L2DLE_PDCP_ENTITY_NUM
#define NR_MAX_L2DLE_PDCP_ENTITY_NUM 32 
#endif 

#ifndef NUP_CACHE_L2TCM_SIZE
#define NUP_CACHE_L2TCM_SIZE 262144 
#endif 

#ifndef NUP_UNCACHE_UNBAK_L2TCM_SIZE
#define NUP_UNCACHE_UNBAK_L2TCM_SIZE 462848 
#endif 

#ifndef NUP_UNCACHE_BAK_L2TCM_SIZE
#define NUP_UNCACHE_BAK_L2TCM_SIZE 61440 
#endif 

#ifndef B5010_FULLSTACK_EMU
#define B5010_FULLSTACK_EMU FEATURE_OFF 
#endif 

#ifndef FEATURE_NR_R16
#define FEATURE_NR_R16 FEATURE_OFF 
#endif 

#ifndef FEATURE_NR_R16_TODO
#define FEATURE_NR_R16_TODO FEATURE_OFF 
#endif 

#ifndef UNALIGNED_ACCESS_HARD_SUPPORT
#define UNALIGNED_ACCESS_HARD_SUPPORT false 
#endif 

#ifndef FEATURE_CUST_OM
#define FEATURE_CUST_OM FEATURE_ON 
#endif 

#ifndef FEATURE_HMS_KIT
#define FEATURE_HMS_KIT FEATURE_OFF 
#endif 

#ifndef FEATURE_CAG
#define FEATURE_CAG FEATURE_OFF 
#endif 

#endif /*__PRODUCT_CONFIG_H__*/ 
