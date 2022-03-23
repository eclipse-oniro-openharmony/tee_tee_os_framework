/*
 * Copyright (C), 2013~2020, Hisilicon Technologies Co., Ltd. All rights reserved.
 */
#ifndef _HI_MODEM_SECBOOT_H_
#define _HI_MODEM_SECBOOT_H_

#include <bsp_param_cfg.h>

#define SOC_LPMCU_Modem_Sysctrl_BASE_ADDR (0xe0200000)
#define HI_SYSCTRL_BASE_ADDR SOC_LPMCU_Modem_Sysctrl_BASE_ADDR

static inline void modem_ccore_unreset(void)
{
    /* 18 unreset a9 */
    UINT32 value = 0;
    writel(0xA040, (unsigned)(HI_SYSCTRL_BASE_ADDR + 0x24));
    value = readl((unsigned)(HI_SYSCTRL_BASE_ADDR + 0x42c));
    value |= 0x1 << 8;
    value |= 0x1 << 9;
    writel(value, (unsigned)(HI_SYSCTRL_BASE_ADDR + 0x42c));
}

static inline void modem_ccore_reset(void)
{
    int i;
    unsigned int *modem_image_size = NULL;

    modem_image_size = hisi_secboot_get_modem_image_size_st();
    if (modem_image_size == NULL) {
        tloge("modem_ccore_reset fail to get modem_image_size.\n");
        return;
    }
    for (i = 0; i < MAX_SOC; i++) {
        modem_image_size[i] = 0;
    }
    /* 18 unreset a9 */
    writel(0x2040, HI_SYSCTRL_BASE_ADDR + 0x20);
    g_modem_load.modem_status = 0;
}

#endif