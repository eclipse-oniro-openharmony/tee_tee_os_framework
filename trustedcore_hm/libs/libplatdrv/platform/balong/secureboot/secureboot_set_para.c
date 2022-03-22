/*
 * Copyright (C), 2013~2020, Hisilicon Technologies Co., Ltd. All rights reserved.
 */
#include <stdint.h>
#include <bsp_modem_product_config.h>
#include <bsp_shared_ddr.h>
#include <bsp_param_cfg.h>
#include <hi_modem_set_para.h>
#include "secboot.h"

#ifdef CONFIG_SYSBOOT_PARA
uint32_t hisi_secboot_set_mem_layout_info(int soc_type, uint32_t base_addr)
{
    void *vir_addr = NULL;
    phy_addr_t phy_addr = 0;
    uint32_t size = 0;

    if (soc_type == MODEM) {
        vir_addr = bsp_mem_share_get("nsroshm_memory_layout", &phy_addr, &size, SHM_NSRO);
        if (vir_addr == NULL) {
            tloge("get memory layout failed!\n");
            return SECBOOT_RET_FAIL_TO_GET_MEM_LAYOUT;
        }
        writel((unsigned int)phy_addr, base_addr + MODEM_MEM_LAYOUT_ADDR_OFFSET);
        writel(size, base_addr + MODEM_MEM_LAYOUT_SIZE_OFFSET);
    }

    return 0;
}
#else
uint32_t hisi_secboot_set_mem_layout_info(int soc_type, uint32_t base_addr)
{
    return 0;
}
#endif
