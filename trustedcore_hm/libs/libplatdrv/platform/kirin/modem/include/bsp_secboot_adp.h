/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2012-2015. All rights reserved.
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

#ifndef __BSP_SECBOOT_ADP_H__
#define __BSP_SECBOOT_ADP_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */
#include "secboot.h"

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3650)

#define DDR_MCORE_ADDR (0x38400000 - 0x80)
#define DDR_MCORE_SIZE    0x5e00000
#define DDR_TLPHY_IMAGE_ADDR (0x38100000 - 0x80)
#define DDR_TLPHY_IMAGE_SIZE 0x300000
#define DDR_MCORE_DTS_ADDR 0x3e200000
#define DDR_MCORE_DTS_SIZE 0x100000

#endif

/*sec boot start */
struct IMAGE_INFO {
	UINT64 ddr_addr;
	unsigned int ddr_size;
	unsigned int unreset_dependcore;
};

/* 存放动态加载的信息，其中
load_cmd 对应动态加载命令，每个bit位对应一个镜像，
和soc_type的值一致，为soc_type的值所在的bit位，
verify_flag对应每个镜像是否校验通过，每个bit位对应一个镜像，
和soc_type的值一致，为soc_type的值所在的bit位，
*/
struct DYNAMIC_LOAD {
	u32 load_cmd;
	u32 verify_flag;
};

/* 存放modem image相关信息，
其中modem_status对应modem的状态，0为复位态，1为解复位态
verify_flag对应各个modem依赖镜像的校验情况，1为校验通过，0为校验未通过，
每个bit位对应一个镜像，
和soc_type的值一致，为soc_type的值所在的bit位，
*/

struct MODEM_LOAD {
	u32 modem_is_ursted;
	u32 verify_flag;
};

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660 \
		|| TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 \
		|| TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6250 \
		|| TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3650 \
		|| TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MIAMICW \
		|| TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)

struct SEC_BOOT_MODEM_INFO {
	struct IMAGE_INFO image_info[MAX_SOC];
	struct DYNAMIC_LOAD dynamic_load;
	u32 aslr_flag;
};
#else
struct verify_param_info
{
    u32 vrl_addr;
    u32 cmd_type;
    u32 image_addr;
    u32 image_size;
    u32 patch_addr;
    u32 patch_size;
    u32 splicing_addr;
    u32 splicing_size;
    u32 deflate_addr;
    u32 deflate_size;
    u32 verify_flag;
    u32 image_id;
};

struct secboot_verify_param
{
    u32 core_idx;
    struct verify_param_info verify_param_info[2];
};

#define MODEM_NUM 3
struct sec_rnd_info
{
    unsigned int image_offset[MODEM_NUM];
    unsigned int stack_guard[MODEM_NUM];
    unsigned int heap_offset[MODEM_NUM];
};

struct SEC_BOOT_MODEM_INFO {
	struct DYNAMIC_LOAD dynamic_load;
	struct IMAGE_INFO image_info[MAX_SOC_MODEM];
	u32 aslr_flag;
	struct secboot_verify_param verify_param;
	struct sec_rnd_info sec_rnd_info;
};
#endif

extern struct MODEM_LOAD g_modem_load;
struct SEC_BOOT_MODEM_INFO *modem_info_base_get(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif

