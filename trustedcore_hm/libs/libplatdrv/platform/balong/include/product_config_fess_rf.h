/* MD5: 6b31effabc900aa44ef3795f86205143*/
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

#if !defined(__PRODUCT_CONFIG_FESS_RF_H__)
#define __PRODUCT_CONFIG_FESS_RF_H__

#ifndef RFIC_BOARD_TYPE_FPGA
#define RFIC_BOARD_TYPE_FPGA 0 
#endif 

#ifndef RFIC_BOARD_TYPE_SFT
#define RFIC_BOARD_TYPE_SFT 1 
#endif 

#ifndef RFIC_BOARD_TYPE_ASIC
#define RFIC_BOARD_TYPE_ASIC 2 
#endif 

#ifndef RFIC_BOARD_TYPE_SDAT
#define RFIC_BOARD_TYPE_SDAT 3 
#endif 

#ifndef RFIC_BOARD_TYPE
#define RFIC_BOARD_TYPE RFIC_BOARD_TYPE_ASIC 
#endif 

#ifndef RFIC_CHIP_TYPE_6365CS
#define RFIC_CHIP_TYPE_6365CS 4 
#endif 

#ifndef RFIC_CHIP_TYPE_6370CS
#define RFIC_CHIP_TYPE_6370CS 5 
#endif 

#ifndef RFIC_CHIP_TYPE_6355ES
#define RFIC_CHIP_TYPE_6355ES 6 
#endif 

#ifndef RFIC_CHIP_TYPE_6366CS
#define RFIC_CHIP_TYPE_6366CS 7 
#endif 

#ifndef HI6365CS_ENABLED
#define HI6365CS_ENABLED 
#endif 

#ifndef HI6370CS_ENABLED
#define HI6370CS_ENABLED 
#endif 

#ifndef HI6355ES_ENABLED
#define HI6355ES_ENABLED 
#endif 

#ifndef HI6355ES_ATE_ENABLED
#define HI6355ES_ATE_ENABLED 
#endif 

#ifndef HI6336CS_ENABLED
#endif 

#ifndef HI6366CS_ENABLED
#define HI6366CS_ENABLED 
#endif 

#ifndef RFDSP_IMAGE_NAME_LIST
#define RFDSP_IMAGE_NAME_LIST rfdsp_hi6365.bin rfdsp_hi6355.bin rfdsp_hi6370.bin rfdsp_hi6366.bin 
#endif 

#ifndef RFDSP_6365CS_IMAGE_NAME
#define RFDSP_6365CS_IMAGE_NAME "rfdsp_hi6365.bin" 
#endif 

#ifndef RFDSP_6355ES_IMAGE_NAME
#define RFDSP_6355ES_IMAGE_NAME "rfdsp_hi6355.bin" 
#endif 

#ifndef RFDSP_6366CS_IMAGE_NAME
#define RFDSP_6366CS_IMAGE_NAME "rfdsp_hi6366.bin" 
#endif 

#ifndef RFDSP_6370CS_IMAGE_NAME
#define RFDSP_6370CS_IMAGE_NAME "rfdsp_hi6370.bin" 
#endif 

#ifndef RFDSP_6365CS_IMAGE_PREFIX
#define RFDSP_6365CS_IMAGE_PREFIX rfdsp_hi6365 
#endif 

#ifndef RFDSP_6355ES_IMAGE_PREFIX
#define RFDSP_6355ES_IMAGE_PREFIX rfdsp_hi6355 
#endif 

#ifndef RFDSP_6366CS_IMAGE_PREFIX
#define RFDSP_6366CS_IMAGE_PREFIX rfdsp_hi6366 
#endif 

#ifndef RFDSP_6370CS_IMAGE_PREFIX
#define RFDSP_6370CS_IMAGE_PREFIX rfdsp_hi6370 
#endif 

#endif /*__PRODUCT_CONFIG_H__*/ 
