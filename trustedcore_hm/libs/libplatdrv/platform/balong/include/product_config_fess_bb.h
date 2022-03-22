/* MD5: 2004723ac1f14539e120f1db4716c69e*/
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

#if !defined(__PRODUCT_CONFIG_FESS_BB_H__)
#define __PRODUCT_CONFIG_FESS_BB_H__

#ifndef BBIC_CHIP_TYPE_HI9510ES
#define BBIC_CHIP_TYPE_HI9510ES 60 
#endif 

#ifndef BBIC_CHIP_TYPE_HI9510CS
#define BBIC_CHIP_TYPE_HI9510CS 61 
#endif 

#ifndef BBIC_CHIP_TYPE_LAGUNA
#define BBIC_CHIP_TYPE_LAGUNA 62 
#endif 

#ifndef BBIC_CHIP_TYPE_LEXINGTON
#define BBIC_CHIP_TYPE_LEXINGTON 63 
#endif 

#ifndef BBIC_CHIP_TYPE_CHARLOTTE
#define BBIC_CHIP_TYPE_CHARLOTTE 64 
#endif 

#ifndef BBIC_CHIP_TYPE_BURBANK
#define BBIC_CHIP_TYPE_BURBANK 65 
#endif 

#ifndef BBIC_CHIP_TYPE
#define BBIC_CHIP_TYPE BBIC_CHIP_TYPE_HI9510CS 
#endif 

#ifndef FESS_FEATURE_SERDES_DEBUG_TEST
#define FESS_FEATURE_SERDES_DEBUG_TEST FEATURE_OFF 
#endif 

#ifndef FESS_RTT_VTF_FFEATURE
#define FESS_RTT_VTF_FFEATURE FEATURE_OFF 
#endif 

#ifndef FESS_FEATURE_ENG_VERSION
#define FESS_FEATURE_ENG_VERSION FEATURE_ON 
#endif 

#ifndef FEATURE_SUPPORT_HF
#define FEATURE_SUPPORT_HF FEATURE_ON 
#endif 

#ifndef FEATURE_SUPPORT_LTEV
#define FEATURE_SUPPORT_LTEV FEATURE_ON 
#endif 

#ifndef FEATURE_SUPPORT_RFIC1
#define FEATURE_SUPPORT_RFIC1 FEATURE_ON 
#endif 

#ifndef FEATURE_EASYRF
#define FEATURE_EASYRF FEATURE_ON 
#endif 

#ifndef RFDSP_TRACE_MEM_SIZE
#define RFDSP_TRACE_MEM_SIZE 2048 
#endif 

#endif /*__PRODUCT_CONFIG_H__*/ 
