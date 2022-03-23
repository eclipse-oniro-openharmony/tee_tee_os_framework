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

#ifndef __BSP_PARAM_CFG_H__
#define __BSP_PARAM_CFG_H__

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

#include <hi_efuse.h>
#include <bsp_security_trng.h>

/* 安全os 与fastboot,ccore交互的空间的基地址，此处在dx的末尾，已经被映射，所以是虚拟地址 */
#define BALONG_PARAM_BASE_ADDR        (0x9ff800)    /* 0x9ff000--0xa00000 */
#define PARAM_MAGIC_OFFSET            (0x0)           /* 魔数:判断参数有效性 */
#define PARAM_CFG_OFFSET              (0x8)           /* 配置参数存放基地址*/

#define IMAGE_ADDR_INVALID_VALUE        (0xFFFFFFFF)

/* 这个枚举的修改需要同步修改一下几个地方
mbb tzdriver
vendor/hisi/system/kernel-4.14/drivers/hisi/tzdriver_hm/teek_client_id.h
mbb secos
vendor/hisi/system/secure_os/trustedcore_hm/prebuild/hm-teeos-release/headers/hm/TEE/tee_common.h(枚举已删除)
vendor/hisi/system/secure_os/trustedcore_hm/libs/hisi-platdrv/platform/balong/include/bsp_param_cfg.h
mbb、phone:ccore modem
vendor/hisi/modem/drv/acore/bootable/bootloader/legacy/modem/include/param_cfg_to_sec.h
vendor/hisi/modem/drv/acore/kernel/drivers/hisi/modem/drv/include/param_cfg_to_sec.h
vendor/hisi/modem/drv/ccore/include/fusion/param_cfg_to_sec.h
vendor/hisi/modem/drv/ccore/include/ccpu/param_cfg_to_sec.h
vendor/hisi/modem/drv/fastboot/include/param_cfg_to_sec.h

phone tzdriver
vendor/hisi/ap/kernel/drivers/tzdriver/teek_client_id.h
phone secos
vendor/thirdparty/secure_os/trustedcore_hm/prebuild/hm-teeos-release/headers/hm/TEE/tee_common.h(枚举已删除)
vendor/thirdparty/secure_os/trustedcore_hm/libs/hisi-platdrv/platform/kirin/secureboot/secboot.h
*/
enum SVC_SECBOOT_IMG_TYPE{
    MODEM = 0,
    HIFI,
    DSP,
    XDSP,
    TAS,
    WAS = 5,
    CAS = 6,
    BOOT = 6, 
    MODEM_DTB,
    ISP,
    NVM,
    NVM_S = 10,
    MBN_R,
    MBN_A,
    MODEM_COMM_IMG,
    MODEM_CERT = 14,
    MODEM_DTO = 14,
    MAX_SOC
};

/*sec boot start */
struct IMAGE_INFO
{
    unsigned long long run_addr;
    unsigned int image_size;
    unsigned int unreset_dependcore;
};

struct MODEM_INFO
{
    unsigned int phy_addr;
    unsigned int virt_addr;
    unsigned int image_addr;
    unsigned int image_size;
    unsigned int unreset_dependcore;
};

/* 存放动态加载的信息，其中
load_cmd 对应动态加载命令，每个bit位对应一个镜像，
和soc_type的值一致，为soc_type的值所在的bit位，
verify_flag对应每个镜像是否校验通过，每个bit位对应一个镜像，
和soc_type的值一致，为soc_type的值所在的bit位，
*/
struct DYNAMIC_LOAD
{
    u32 load_cmd;
    u32 verify_flag;
};

/* 存放modem image相关信息，
其中modem_status对应modem的状态，0为复位态，1为解复位态
verify_flag对应各个modem依赖镜像的校验情况，1为校验通过，0为校验未通过，
每个bit位对应一个镜像，
和soc_type的值一致，为soc_type的值所在的bit位，
*/

struct MODEM_LOAD
{
    u32 modem_status;
    u32 verify_flag;
};

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

struct verify_result_info {
    u32 image_id;
    u32 cmd_type;
    u32 verify_flag;
    u32 ret;
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

struct SEC_BOOT_MODEM_INFO
{
    struct DYNAMIC_LOAD dynamic_load;
    struct IMAGE_INFO image_info[MAX_SOC];
    u32 aslr_flag;
    struct secboot_verify_param verify_param;
    struct sec_rnd_info sec_rnd_info;
};

/*sec boot end */

struct PARAM_CFG
{
    unsigned int   magic;                   /* 魔数，标识配置参数的状态 */
    unsigned int   protect_barrier_size;    /* 预留(4K)防止被踩，初始化为全F */
    unsigned int   param_cfg_size;          /* 配置参数预留(16K)大小 */
    u64   icc_channel_base_addr;
    unsigned int   icc_channel_max_size;
    struct SEC_BOOT_MODEM_INFO sec_boot_modem_info;
    unsigned char trng_buf[SHARE_TRNG_LENGTH];
    u32   efuse_val[EFUSE_MAX_SIZE];
};

struct hisi_secboot_msg_s {
    struct verify_param_info verify_info;
    struct verify_result_info verify_result;
};

extern struct MODEM_INFO g_image_info[MAX_SOC];
extern struct MODEM_LOAD g_modem_load;
struct PARAM_CFG *bsp_cfg_base_addr_get(void);
unsigned int *hisi_secboot_get_modem_image_size_st(void);
int hisi_secboot_send_msg_to_cp(struct verify_result_info *verify_result);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif

