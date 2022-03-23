/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: plat_cfg defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2021-01
 */

#include "plat_cfg.h"
#include "plat_cfg_public.h"
#include <plat_features.h>
#include "uart_register.h"

struct platform_info g_plat_cfg = {
    .phys_region_start      = 0,
    .phys_region_size       = TEEOS_MEM_SIZE,
    .uart_addr = UART_ADDR,
    .uart_type = PL011_TYPE | UART_ENABLE_FLAG,
    .shmem_offset         = TEEOS_MEM_SIZE,
    .shmem_size           = 0,

    .gic_config = {
        .version = GIC_V2_VERSION,
        .v2 = {
            .dist = { GIC_V2_DIST_ADDR, GIC_V2_DIST_ADDR + PAGE_SIZE },
            .contr = { GIC_V2_CONTR_ADDR, GIC_V2_CONTR_ADDR + PAGE_SIZE },
        }
    },

    .spi_num_for_notify     = SPI_NUM,

    .plat_features          = PLAT_DEF_ENG
#ifdef CONFIG_ARM64_PAN
    | PLAT_ENABLE_PAN
#endif
    ,

    /* at most PLAT_MAX_DEVIO_REGIONS (128) regions */
    .plat_io_regions        = {
        { 0, 0 } /* this is terminator */
    }
};
