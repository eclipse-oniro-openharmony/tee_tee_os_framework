/* MD5: fc8814eab271fa05455162e252d20664*/
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

#if !defined(__PRODUCT_CONFIG_UPHY_V110_H__)
#define __PRODUCT_CONFIG_UPHY_V110_H__

#ifndef UPHY_PLATFORM
#define UPHY_PLATFORM UPHY_ASIC 
#endif 

#ifndef LPS_RTT
#endif 

#ifndef UPHY_OM_SAFE_MODE
#endif 

#ifndef UPHY_RTT_TEST_ENABLED
#define UPHY_RTT_TEST_ENABLED 
#endif 

#ifndef LTEV_FEATURE_ENABLED
#define LTEV_FEATURE_ENABLED 
#endif 

#ifndef GSM_FEATURE_ENABLED
#define GSM_FEATURE_ENABLED 
#endif 

#ifndef WCDMA_FEATURE_ENABLED
#define WCDMA_FEATURE_ENABLED 
#endif 

#ifndef UPHY_L2M_SIZE_SOFT
#define UPHY_L2M_SIZE_SOFT 0x500000 
#endif 

#ifndef UPHY_L2M_SIZE_HARD
#define UPHY_L2M_SIZE_HARD 0x540000 
#endif 

#ifndef UPHY_IMAGE_SIZE
#define UPHY_IMAGE_SIZE 0x1200000 
#endif 

#ifndef UPHY_L2M_NR_HL1C_PRIV_DATA_SIZE
#define UPHY_L2M_NR_HL1C_PRIV_DATA_SIZE (96*1024) 
#endif 

#ifndef UPHY_DDR_NR_HL1C_PRIV_DATA_SIZE
#define UPHY_DDR_NR_HL1C_PRIV_DATA_SIZE (8*1024) 
#endif 

#ifndef UPHY_L2M_NR_LL1D_PRIV_DATA_SIZE
#define UPHY_L2M_NR_LL1D_PRIV_DATA_SIZE (64*1024) 
#endif 

#ifndef UPHY_DDR_NR_LL1D_PRIV_DATA_SIZE
#define UPHY_DDR_NR_LL1D_PRIV_DATA_SIZE (80*1024) 
#endif 

#ifndef UPHY_L2M_NR_LL1U_PRIV_DATA_SIZE
#define UPHY_L2M_NR_LL1U_PRIV_DATA_SIZE (136*1024) 
#endif 

#ifndef UPHY_DDR_NR_LL1U_PRIV_DATA_SIZE
#define UPHY_DDR_NR_LL1U_PRIV_DATA_SIZE (24*1024) 
#endif 

#ifndef UPHY_L2M_LR_HL1C_PRIV_DATA_SIZE
#define UPHY_L2M_LR_HL1C_PRIV_DATA_SIZE (0) 
#endif 

#ifndef UPHY_DDR_LR_HL1C_PRIV_DATA_SIZE
#define UPHY_DDR_LR_HL1C_PRIV_DATA_SIZE (104*1024) 
#endif 

#ifndef UPHY_L2M_LR_LL1D_PRIV_DATA_SIZE
#define UPHY_L2M_LR_LL1D_PRIV_DATA_SIZE (0) 
#endif 

#ifndef UPHY_DDR_LR_LL1D_PRIV_DATA_SIZE
#define UPHY_DDR_LR_LL1D_PRIV_DATA_SIZE (40*1024) 
#endif 

#ifndef UPHY_L2M_LR_LL1U_PRIV_DATA_SIZE
#define UPHY_L2M_LR_LL1U_PRIV_DATA_SIZE (0) 
#endif 

#ifndef UPHY_DDR_LR_LL1U_PRIV_DATA_SIZE
#define UPHY_DDR_LR_LL1U_PRIV_DATA_SIZE (24*1024) 
#endif 

#ifndef UPHY_L2M_GSM_PRIV_DATA_SIZE
#define UPHY_L2M_GSM_PRIV_DATA_SIZE (0) 
#endif 

#ifndef UPHY_L2M_WCDMA_PRIV_DATA_SIZE
#define UPHY_L2M_WCDMA_PRIV_DATA_SIZE (0) 
#endif 

#ifndef UPHY_VADDR_SIZE
#define UPHY_VADDR_SIZE 0x200000 
#endif 

#endif /*__PRODUCT_CONFIG_H__*/ 
