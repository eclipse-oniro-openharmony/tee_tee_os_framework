/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "plat_cfg.h"
#include "plat_cfg_public.h"
#include <plat_features.h>
#include "uart_register.h"

struct platform_info g_plat_cfg = {
    /*
     * To config, set TRUSTEDCORE_PHY_TEXT_BASE in common/var.mk
     * value is assigned in boot_kernel_on_current_cpu function
     */
    .phys_region_start = 0,
    .uart_addr = UART_ADDR,
    .uart_type = UART_ENABLE_FLAG | PL011_TYPE,
    .shmem_offset = SHMEM_OFFSET,
    .shmem_size           = SHMEM_SIZE,
    /* 6 MB */
    .phys_region_size = TEEOS_MEM_SIZE,

    .gic_config = {
        .version = GIC_V2_VERSION,
        .v2 = {
            .dist = { GIC_V2_DIST_BASE, GIC_V2_DIST_BASE + PAGE_SIZE },
            .contr = { GIC_V2_CPU_BASE, GIC_V2_CPU_BASE + PAGE_SIZE },
        }
    },

    .spi_num_for_notify = HI3516_SPI_NUM,

    .plat_features = PLAT_DEF_ENG,

    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions */
    .extend_datas_io = {
        .extend_magic = 0,
        .extend_length = 0,
        .extend_paras = {0},
        .plat_io_regions = {
            /* .start, .end */
            /* the first region should be UART6 */
            { CPU_CTLR_ADDR, CPU_CTLR_ADDR + CPU_CTLR_SIZE },
            /* this is terminator */
            { 0, 0 }
        }
    }
};
