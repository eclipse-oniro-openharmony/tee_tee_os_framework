
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
#include <sre_typedef.h>
#include <mem_page_ops.h>
#include <tee_log.h> /* uart_printf_func */
#include <drv_mem.h> /* sre_mmap */
#include <register_ops.h>
#include <bsp_param_cfg.h>
#include <osl_balong.h>
#include <bsp_security_trng.h>
#include <bsp_shared_ddr.h>
#include "boot_sharedmem.h"

struct PARAM_CFG *g_param_cfg = NULL;

int bsp_param_cfg_init(void)
{
    int ret = 0;
    u64 cfg_base_phy, temp;
    u32 cfg_base_virt;
    char balong_param_base_addr[0x20];

    if (get_shared_mem_info(TEEOS_SHARED_MEM_MAILBOX, (u32 *)balong_param_base_addr,
                               sizeof(balong_param_base_addr))) {
        uart_printf_func("Error!!!failed to get shared mem info\n");
        return -1;
    }

    writel(0xdeadbeef, (u32)(balong_param_base_addr + PARAM_MAGIC_OFFSET));
    cfg_base_phy = DDR_SEC_SHARED_ADDR + SHM_OFFSET_PARAM_CFG;
    writel(cfg_base_phy & 0xffffffff, (u32)(balong_param_base_addr + PARAM_CFG_OFFSET));
    temp = cfg_base_phy >> 32;
    writel(temp, (u32)(balong_param_base_addr + PARAM_CFG_OFFSET + 4));

    if (sre_mmap(cfg_base_phy, sizeof(struct PARAM_CFG), &cfg_base_virt, secure, non_cache)) {
        uart_printf_func("cfg_baseh = 0x%x,cfg_basel = 0x%x\n", (u32)(cfg_base_phy >> 32), (u32)cfg_base_phy);
        return -1;
    }

    g_param_cfg = (struct PARAM_CFG *)cfg_base_virt;
    g_param_cfg->magic = 0xeaeaeaea;
#ifdef CONFIG_MODEM_TRNG
    ret = trng_seed_get(g_param_cfg->trng_buf, SHARE_TRNG_LENGTH);
    if (ret != 0) {
        uart_printf_func("trng_seed_get return error.\n");
        return 0;
    }
#endif
    tloge("bsp_param_cfg_init ok.\n");
    return 0;
}

struct PARAM_CFG *bsp_cfg_base_addr_get(void)
{
    if (NULL == g_param_cfg) {
        uart_printf_func("invalid g_param_cfg\n");
        return NULL;
    }
    return g_param_cfg;
}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_BALTIMORE && TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
/*lint -e528 -esym(528,*)*/
DECLARE_TC_DRV(param_cfg, 0, 0, 0, TC_DRV_MODULE_INIT, bsp_param_cfg_init, NULL, NULL, NULL, NULL);
/*lint -e528 +esym(528,*)*/
#endif
