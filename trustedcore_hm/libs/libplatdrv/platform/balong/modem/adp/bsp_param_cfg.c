/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 */
#include <bsp_modem_product_config.h>
#include <register_ops.h>
#include <drv_module.h>
#include <drv_mem.h>
#include <sre_typedef.h>
#include <bsp_param_cfg.h>
#include "mem_ops.h"
#include <bsp_security_trng.h>
#include <bsp_shared_ddr.h>
#include <bsp_memory_layout.h>
#include "tee_log.h"

#ifdef CONFIG_PARAM_CFG_OFFSET
struct PARAM_CFG *g_param_cfg = NULL;
#endif
struct MODEM_INFO g_image_info[MAX_SOC];
struct MODEM_LOAD g_modem_load;
u32 g_modem_aslr_flag;

int bsp_param_cfg_init(void)
{
    int i;
    unsigned int *modem_image_size = NULL;
#ifdef CONFIG_PARAM_CFG_OFFSET
    int ret;
    unsigned int nv_type;
    unsigned int cfg_base, cfg_size;
    struct PARAM_CFG *cfg_base_virt = NULL;
#endif

    modem_image_size = hisi_secboot_get_modem_image_size_st();
    if (modem_image_size == NULL) {
        uart_printf_func("bsp_param_cfg_init get modem_image_size failed!\n");
        return 0;
    }

    for (i = 0; i < MAX_SOC; i++) {
        modem_image_size[i] = 0;
    }

#ifdef CONFIG_PARAM_CFG_OFFSET
    cfg_base_virt = bsp_mem_share_get("seshm_param_cfg", (phy_addr_t *)&cfg_base, &cfg_size, SHM_SEC);
    g_param_cfg = cfg_base_virt;
    g_param_cfg->magic = 0xeaeaeaea;
#endif
    /* 初始化modem状态 */
    g_modem_load.modem_status = 0; /* 复位态 */
    g_modem_load.verify_flag = 0;  /* 所有镜像均未校验或未校验通过 */

#ifdef CONFIG_MODEM_BALONG_ASLR
    g_modem_aslr_flag = 1;
#endif
    g_image_info[MODEM].phy_addr = mdrv_mem_region_get("mdm_ddr", &(g_image_info[MODEM].image_size));
    g_image_info[MODEM].image_addr = IMAGE_ADDR_INVALID_VALUE;
    g_image_info[MODEM].unreset_dependcore = 1 << MODEM;
    if (map_from_ns_page(g_image_info[MODEM].phy_addr, g_image_info[MODEM].image_size,
                            &(g_image_info[MODEM].virt_addr), secure)) {
        uart_printf_func("%s, map data buffer addr=0x%x size=0x%x error\n", __func__, g_image_info[MODEM].phy_addr,
                         g_image_info[MODEM].image_size);
    }

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI9510)
    for (nv_type = NVM; nv_type <= MBN_A; nv_type++) {
        g_image_info[nv_type].phy_addr = g_param_cfg->sec_boot_modem_info.image_info[nv_type].run_addr;
        g_image_info[nv_type].image_addr = IMAGE_ADDR_INVALID_VALUE;
        g_image_info[nv_type].image_size = g_param_cfg->sec_boot_modem_info.image_info[nv_type].image_size;
        g_image_info[nv_type].unreset_dependcore =
            g_param_cfg->sec_boot_modem_info.image_info[nv_type].unreset_dependcore;

        if (map_from_ns_page(g_image_info[nv_type].phy_addr, g_image_info[nv_type].image_size,
                             &(g_image_info[nv_type].virt_addr), secure)) {
            uart_printf_func("%s, map data buffer addr=0x%x size=0x%x error\n", __func__,
                             g_image_info[nv_type].phy_addr, g_image_info[nv_type].image_size);
        }
    }
#endif
#ifdef CONFIG_PARAM_CFG_OFFSET
    ret = trng_seed_get(g_param_cfg->trng_buf, SHARE_TRNG_LENGTH);
    if (ret != 0) {
        uart_printf_func("trng_seed_get return error.\n");
        return 0;
    }
#endif

    uart_printf_func("bsp_param_cfg init ok\n");
    return 0;
}

#ifdef CONFIG_PARAM_CFG_OFFSET
struct PARAM_CFG *bsp_cfg_base_addr_get(void)
{
    if (NULL == g_param_cfg) {
        uart_printf_func("invalid g_param_cfg\n");
        return NULL;
    }
    return g_param_cfg;
}
#endif

DECLARE_TC_DRV(param_cfg, 0, 0, 0, 0, bsp_param_cfg_init, NULL, NULL, NULL, NULL);

