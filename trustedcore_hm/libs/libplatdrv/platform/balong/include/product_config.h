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

#if !defined(__PRODUCT_CONFIG_H__)
#define __PRODUCT_CONFIG_H__
#if defined(CHIP_TYPE_MODEM_ES)

#include "product_config_version.h"
#include "product_config_ddr_es.h"

#if defined(HISI_MCU)
#include "product_config_drv_mcu_es.h"

#elif defined(HISI_HITSP)
#include "product_config_drv_tsp_es.h"
#include "product_config_pam.h"
#include "product_config_gucas.h"
#include "product_config_gucnas.h"
#include "product_config_fess_bb_es.h"
#include "product_config_fess_rf.h"
#include "product_config_gucphy.h"
#include "product_config_tlphy.h"
#include "product_config_uphy_es.h"
#include "product_config_gphy.h"
#include "product_config_wphy.h"
#include "product_config_lphy.h"
#include "product_config_nphy.h"
#include "product_config_tlps.h"
#include "product_config_audio.h"
#include "product_config_nrps_es.h"

#elif defined(HISI_HITVP)
#include "product_config_drv_tvp_es.h"
#include "product_config_gucphy.h"
#include "product_config_tlphy.h"
#include "product_config_uphy_es.h"
#include "product_config_gphy.h"
#include "product_config_wphy.h"
#include "product_config_lphy.h"
#include "product_config_nphy.h"
#else 
#include "product_config_drv_ap_es.h"
#include "product_config_pam.h"
#include "product_config_gucas.h"
#include "product_config_gucnas.h"
#include "product_config_fess_bb_es.h"
#include "product_config_fess_rf.h"
#include "product_config_tlps.h"
#include "product_config_gucphy.h"
#include "product_config_tlphy.h"
#include "product_config_uphy_es.h"
#include "product_config_gphy.h"
#include "product_config_wphy.h"
#include "product_config_lphy.h"
#include "product_config_nphy.h"
#include "product_config_audio.h"
#include "product_config_tool.h"
#include "product_config_nrps_es.h"
#endif
#else   /* ndef CHIP_TYPE_MODEM_ES */

#if defined(CHIP_TYPE_MODEM_V110)
/* cs v110 */
#include "product_config_version.h"
#include "product_config_ddr.h"

#if defined(HISI_MCU)
#include "product_config_drv_mcu.h"

#elif defined(HISI_HITSP)
#include "product_config_drv_tsp.h"
#include "product_config_pam.h"
#include "product_config_gucas.h"
#include "product_config_gucnas.h"
#include "product_config_fess_bb.h"
#include "product_config_fess_rf.h"
#include "product_config_gucphy.h"
#include "product_config_tlphy.h"
#include "product_config_uphy_v110.h"
#include "product_config_gphy.h"
#include "product_config_wphy.h"
#include "product_config_lphy.h"
#include "product_config_nphy.h"
#include "product_config_tlps.h"
#include "product_config_audio.h"
#include "product_config_nrps.h"

#elif defined(HISI_HITVP)
#include "product_config_drv_tvp.h"
#include "product_config_gucphy.h"
#include "product_config_tlphy.h"
#include "product_config_uphy_v110.h"
#include "product_config_gphy.h"
#include "product_config_wphy.h"
#include "product_config_lphy.h"
#include "product_config_nphy.h"
#else 
#include "product_config_drv_ap.h"
#include "product_config_pam.h"
#include "product_config_gucas.h"
#include "product_config_gucnas.h"
#include "product_config_fess_bb.h"
#include "product_config_fess_rf.h"
#include "product_config_tlps.h"
#include "product_config_gucphy.h"
#include "product_config_tlphy.h"
#include "product_config_uphy_v110.h"
#include "product_config_gphy.h"
#include "product_config_wphy.h"
#include "product_config_lphy.h"
#include "product_config_nphy.h"
#include "product_config_audio.h"
#include "product_config_tool.h"
#include "product_config_nrps.h"
#endif

#else   /* ndef CHIP_TYPE_MODEM_ES and ndef CHIP_TYPE_MODEM_V110 */
/*new config.h */
#include "product_config_version.h"
#include "product_config_ddr.h"

#if defined(HISI_MCU)
#include "product_config_drv_mcu.h"

#elif defined(HISI_HITSP)
#include "product_config_drv_tsp.h"
#include "product_config_pam.h"
#include "product_config_gucas.h"
#include "product_config_gucnas.h"
#include "product_config_fess_bb.h"
#include "product_config_fess_rf.h"
#include "product_config_gucphy.h"
#include "product_config_tlphy.h"
#include "product_config_uphy.h"
#include "product_config_gphy.h"
#include "product_config_wphy.h"
#include "product_config_lphy.h"
#include "product_config_nphy.h"
#include "product_config_tlps.h"
#include "product_config_audio.h"
#include "product_config_nrps.h"

#elif defined(HISI_HITVP)
#include "product_config_drv_tvp.h"
#include "product_config_gucphy.h"
#include "product_config_tlphy.h"
#include "product_config_uphy.h"
#include "product_config_gphy.h"
#include "product_config_wphy.h"
#include "product_config_lphy.h"
#include "product_config_nphy.h"
#else 
#include "product_config_drv_ap.h"
#include "product_config_pam.h"
#include "product_config_gucas.h"
#include "product_config_gucnas.h"
#include "product_config_fess_bb.h"
#include "product_config_fess_rf.h"
#include "product_config_tlps.h"
#include "product_config_gucphy.h"
#include "product_config_tlphy.h"
#include "product_config_uphy.h"
#include "product_config_gphy.h"
#include "product_config_wphy.h"
#include "product_config_lphy.h"
#include "product_config_nphy.h"
#include "product_config_audio.h"
#include "product_config_tool.h"
#include "product_config_nrps.h"
#endif
#endif

#endif
#endif /*__PRODUCT_CONFIG_H__*/
