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
 #include <product_config_drv.h>
#include <drv_module.h>
#include <drv_mem.h> /* sre_mmap */
#include <sre_typedef.h>
#include <sre_debug.h> /* uart_printf */
#include <bsp_param_cfg.h>
#include <bsp_secboot_adp.h>
#include <bsp_modem_nvim.h>
#include "mem_page_ops.h"
#include "tee_log.h" /* uart_printf_func */
#include "securec.h"

struct MODEM_LOAD g_modem_load;
u32 g_modem_aslr_flag;

void bsp_secboot_modem_info_init(void)
{
    g_image_info[MODEM].ddr_phy_addr = DDR_MCORE_ADDR;
    g_image_info[MODEM].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM].ddr_size = DDR_MCORE_SIZE;
    g_image_info[MODEM].unreset_dependcore = (1 << MODEM) | (1 << DSP);

    g_image_info[DSP].ddr_phy_addr = DDR_TLPHY_IMAGE_ADDR;
    g_image_info[DSP].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[DSP].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[DSP].ddr_size = DDR_TLPHY_IMAGE_SIZE;
    g_image_info[DSP].unreset_dependcore = 0;

    g_image_info[MODEM_DTB].ddr_phy_addr = DDR_MCORE_DTS_ADDR;
    g_image_info[MODEM_DTB].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM_DTB].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM_DTB].ddr_size = DDR_MCORE_DTS_SIZE;
    g_image_info[MODEM_DTB].unreset_dependcore = 0;
}

void bsp_secboot_modem_init(void) {
    g_image_info[MODEM].ddr_phy_addr = DDR_MCORE_ADDR;
    g_image_info[MODEM].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM].ddr_size = DDR_MCORE_SIZE;
#ifdef CONFIG_COLD_PATCH_BORROW_DDR
    g_image_info[MODEM].ddr_size += DDR_MCORE_NR_SIZE;
#endif
    g_image_info[MODEM].unreset_dependcore = g_image_info[MODEM].unreset_dependcore | (1 << MODEM);
    g_image_info[MODEM].image_size = 0;
}

void bsp_secboot_dsp_init(void) {
#if (defined(CONFIG_PHY_LOAD))
    g_image_info[DSP].ddr_phy_addr = DDR_TLPHY_IMAGE_ADDR;
    g_image_info[DSP].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[DSP].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[DSP].ddr_size = DDR_TLPHY_IMAGE_SIZE;
    g_image_info[DSP].unreset_dependcore = 0;
    g_image_info[DSP].image_size = 0;

#ifndef CONFIG_MLOADER
    g_image_info[MODEM].unreset_dependcore = g_image_info[MODEM].unreset_dependcore | (1 << DSP);
#ifdef CONFIG_RFIC_LOAD
    g_image_info[RFIC].ddr_phy_addr = DDR_RFIC_IMAGE_ADDR;
    g_image_info[RFIC].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[RFIC].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[RFIC].ddr_size = DDR_RFIC_IMAGE_SIZE;
    g_image_info[RFIC].unreset_dependcore = 0;
    g_image_info[RFIC].image_size = 0;

    g_image_info[MODEM].unreset_dependcore = g_image_info[MODEM].unreset_dependcore | (1 << RFIC);
#endif
#endif
#else
#ifdef CONFIG_TLPHY_LOAD
    g_image_info[DSP].ddr_phy_addr = DDR_TLPHY_IMAGE_ADDR;
    g_image_info[DSP].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[DSP].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[DSP].ddr_size = DDR_TLPHY_IMAGE_SIZE;
    g_image_info[DSP].unreset_dependcore = 0;
    g_image_info[DSP].image_size = 0;
#ifndef CONFIG_MLOADER
    g_image_info[MODEM].unreset_dependcore = g_image_info[MODEM].unreset_dependcore | (1 << DSP);
#endif
#endif
#ifdef CONFIG_CPHY_LOAD
    g_image_info[XDSP].ddr_phy_addr = DDR_CBBE_IMAGE_ADDR;
    g_image_info[XDSP].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[XDSP].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[XDSP].ddr_size = DDR_CBBE_IMAGE_SIZE;
    g_image_info[XDSP].unreset_dependcore = 0;
    g_image_info[XDSP].image_size = 0;
#ifndef CONFIG_MLOADER
    g_image_info[MODEM].unreset_dependcore = g_image_info[MODEM].unreset_dependcore | (1 << XDSP);
#endif
#endif
#endif
}

void bsp_secboot_dts_init(void)
{
    g_image_info[MODEM_DTB].ddr_phy_addr = DDR_MCORE_DTS_ADDR;
    g_image_info[MODEM_DTB].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM_DTB].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM_DTB].ddr_size = DDR_MCORE_DTS_SIZE;
    g_image_info[MODEM_DTB].unreset_dependcore = 0;
    g_image_info[MODEM_DTB].image_size = 0;
#ifdef CONFIG_IS_DTB_VERIFY
    g_image_info[MODEM].unreset_dependcore = g_image_info[MODEM].unreset_dependcore | (1 << MODEM_DTB);
#endif
#ifdef CONFIG_ENABLE_DTO
    g_image_info[MODEM_DTO].ddr_phy_addr = DDR_LRCCPU_DTBO_ADDR;
    g_image_info[MODEM_DTO].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM_DTO].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM_DTO].ddr_size = DDR_MDTS_OVERLAY_SIZE;
    g_image_info[MODEM_DTO].unreset_dependcore = 0;
    g_image_info[MODEM_DTO].image_size = 0;
#ifdef CONFIG_IS_DTB_VERIFY
    g_image_info[MODEM].unreset_dependcore = g_image_info[MODEM].unreset_dependcore | (1 << MODEM_DTO);
#endif
#endif
}

void bsp_secboot_nv_init(void)
{
#ifdef CONFIG_HISI_NVIM_SEC
    unsigned int file_info_virt;
    unsigned int file_info_phy;
    nv_file_info_s* file_info = NULL;

    file_info_phy = NV_GLOBAL_CTRL_INFO_ADDR + NV_GLOBAL_CTRL_INFO_SIZE;

    if (sre_mmap(file_info_phy, sizeof(nv_file_info_s), &file_info_virt, secure, non_cache)) {
        tloge("file_info_phy = 0x%x, file_info_virt = 0x%x\n", file_info_phy, file_info_virt);
        return;
    }
    file_info = (nv_file_info_s*)(uintptr_t)file_info_virt;

    g_image_info[NVM].ddr_phy_addr = NV_GLOBAL_CTRL_INFO_ADDR + file_info[NV_FILE_ATTRIBUTE_RDWR - 1].file_offset;
    g_image_info[NVM].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[NVM].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[NVM].ddr_size = file_info[NV_FILE_ATTRIBUTE_RDWR - 1].file_size;
    g_image_info[NVM].unreset_dependcore = 0;
    g_image_info[NVM].image_size = 0;
    tloge("bsp secboot nv init ok.\n");

#endif
}

void bsp_secboot_patch_init(void)
{
#ifdef CONFIG_COLD_PATCH
    g_image_info[MODEM_COLD_PATCH].ddr_phy_addr = DDR_MCORE_ADDR;
    g_image_info[MODEM_COLD_PATCH].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM_COLD_PATCH].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM_COLD_PATCH].ddr_size = DDR_MCORE_SIZE;
    g_image_info[MODEM_COLD_PATCH].unreset_dependcore = 0;
    g_image_info[MODEM_COLD_PATCH].image_size = 0;

    g_image_info[DSP_COLD_PATCH].ddr_phy_addr = DDR_MCORE_ADDR;
    g_image_info[DSP_COLD_PATCH].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[DSP_COLD_PATCH].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[DSP_COLD_PATCH].ddr_size = DDR_MCORE_SIZE;
    g_image_info[DSP_COLD_PATCH].unreset_dependcore = 0;
    g_image_info[DSP_COLD_PATCH].image_size = 0;

#endif

#ifdef CONFIG_MODEM_COLD_PATCH
    g_image_info[MODEM_COLD_PATCH].ddr_phy_addr = DDR_MCORE_ADDR;
    g_image_info[MODEM_COLD_PATCH].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM_COLD_PATCH].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM_COLD_PATCH].ddr_size = DDR_MCORE_SIZE;
#ifdef CONFIG_COLD_PATCH_BORROW_DDR
    g_image_info[MODEM_COLD_PATCH].ddr_size += DDR_MCORE_NR_SIZE;
#endif
    g_image_info[MODEM_COLD_PATCH].unreset_dependcore = 0;
    g_image_info[MODEM_COLD_PATCH].image_size = 0;
#endif
}

void bsp_secboot_aslr_init(void)
{
#ifdef CONFIG_MODEM_BALONG_ASLR
    g_modem_aslr_flag = 1;
#endif
}
int bsp_secboot_adp_init(void)
{
    int i;
    struct PARAM_CFG *cfg_base = bsp_cfg_base_addr_get();

    /* init */
    g_modem_load.modem_is_ursted = 0; /* 初始化modem状态 */
    g_modem_load.verify_flag = 0;     /* 初始化校验标记 */
    for (i = 0; i < MAX_SOC; i++) {
        g_image_info[i].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    }

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3650)
    bsp_secboot_modem_info_init();
#else

    if (NULL == cfg_base) {
        uart_printf_func("get cfg_base_addr failed, is singleap version?\n");
        return 0;
    }

    bsp_secboot_modem_init();
    bsp_secboot_dsp_init();
    bsp_secboot_dts_init();
    bsp_secboot_nv_init();
    bsp_secboot_patch_init();
    bsp_secboot_aslr_init();
#endif

    (void)memset_s(&(cfg_base->sec_boot_modem_info), sizeof(struct SEC_BOOT_MODEM_INFO), 0, sizeof(struct SEC_BOOT_MODEM_INFO));
    for (i = 0; i < MAX_SOC_MODEM; i++) {
        cfg_base->sec_boot_modem_info.image_info[i].ddr_addr = g_image_info[i].ddr_phy_addr;
        cfg_base->sec_boot_modem_info.image_info[i].ddr_size = g_image_info[i].ddr_size;
        cfg_base->sec_boot_modem_info.image_info[i].unreset_dependcore = g_image_info[i].unreset_dependcore;
    }
    cfg_base->sec_boot_modem_info.aslr_flag = g_modem_aslr_flag;
    tloge("bsp secboot adp init ok.\n");
    return 0;
}

struct SEC_BOOT_MODEM_INFO *modem_info_base_get(void)
{
    struct PARAM_CFG *cfg_base = bsp_cfg_base_addr_get();

    if (NULL == cfg_base) {
        uart_printf_func("modem info base get failed, invalied cfg base.\n");
        return NULL;
    } else {
        return &(cfg_base->sec_boot_modem_info);
    }
}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_BALTIMORE && TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
/*lint -e528 -esym(528,*)*/
DECLARE_TC_DRV(secboot_adp, 0, 0, 0, TC_DRV_MODULE_INIT, bsp_secboot_adp_init, NULL, NULL, NULL, NULL);
/*lint -e528 +esym(528,*)*/
#endif
