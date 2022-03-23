/*
 * Copyright (C), 2013~2020, Hisilicon Technologies Co., Ltd. All rights reserved.
 */
#ifndef _HI_MODEM_SECBOOT_H_
#define _HI_MODEM_SECBOOT_H_

#include <bsp_param_cfg.h>
#include "tee_log.h"

#define HI_CS_TSP_REG_DSS0_UNRESET_ADDR 0xF584D0A0
#define HI_CS_TSP_REG_DSS1_UNRESET_ADDR 0xF588D0A0
#define HI_CS_TSP_REG_DSS2_UNRESET_ADDR 0xF58cD0A0

#define HI_ES_TSP_REG_DSS0_UNRESET_ADDR 0xE184D0A0
#define HI_ES_TSP_REG_DSS1_UNRESET_ADDR 0xE188D0A0
#define HI_ES_TSP_REG_DSS2_UNRESET_ADDR 0xE18CD0A0
#define HI_ES_TSP_REG_DSS3_UNRESET_ADDR 0xE190D0A0

#define HI_ES_TSP_SYSCTRL_DSS0_T0_PC 0xE186102C
#define HI_ES_TSP_SYSCTRL_DSS0_T1_PC 0xE186902C
#define HI_ES_TSP_SYSCTRL_DSS0_T2_PC 0xE187102C
#define HI_ES_TSP_SYSCTRL_DSS0_T3_PC 0xE187902C

#define HI_ES_TSP_SYSCTRL_DSS1_T0_PC 0xE18A102C
#define HI_ES_TSP_SYSCTRL_DSS1_T1_PC 0xE18A902C
#define HI_ES_TSP_SYSCTRL_DSS1_T2_PC 0xE18B102C
#define HI_ES_TSP_SYSCTRL_DSS1_T3_PC 0xE18B902C

#define HI_ES_TSP_SYSCTRL_DSS2_T0_PC 0xE18E102C
#define HI_ES_TSP_SYSCTRL_DSS2_T1_PC 0xE18E902C
#define HI_ES_TSP_SYSCTRL_DSS2_T2_PC 0xE18F102C
#define HI_ES_TSP_SYSCTRL_DSS2_T3_PC 0xE18F902C

#define HI_ES_TSP_SYSCTRL_DSS3_T0_PC 0xE192102C
#define HI_ES_TSP_SYSCTRL_DSS3_T1_PC 0xE192902C
#define HI_ES_TSP_SYSCTRL_DSS3_T2_PC 0xE193102C
#define HI_ES_TSP_SYSCTRL_DSS3_T3_PC 0xE193902C

#define HI_CS_TSP_SYSCTRL_DSS0_T0_PC 0xF586102C
#define HI_CS_TSP_SYSCTRL_DSS0_T1_PC 0xF586902C
#define HI_CS_TSP_SYSCTRL_DSS0_T2_PC 0xF587102C
#define HI_CS_TSP_SYSCTRL_DSS0_T3_PC 0xF587902C

#define HI_CS_TSP_SYSCTRL_DSS1_T0_PC 0xF58A102C
#define HI_CS_TSP_SYSCTRL_DSS1_T1_PC 0xF58A902C
#define HI_CS_TSP_SYSCTRL_DSS1_T2_PC 0xF58B102C
#define HI_CS_TSP_SYSCTRL_DSS1_T3_PC 0xF58B902C

#define HI_CS_TSP_SYSCTRL_DSS2_T0_PC 0xF58E102C
#define HI_CS_TSP_SYSCTRL_DSS2_T1_PC 0xF58E902C
#define HI_CS_TSP_SYSCTRL_DSS2_T2_PC 0xF58F102C
#define HI_CS_TSP_SYSCTRL_DSS2_T3_PC 0xF58F902C


#ifdef CONFIG_MODEM_SECBOOT_ES
static inline void modem_ccore_unreset(void)
{
    u32 reg;

    /* unreset for dss0-3 */
    reg = readl(HI_ES_TSP_REG_DSS0_UNRESET_ADDR);
    reg |= 0x9;
    writel(reg, HI_ES_TSP_REG_DSS0_UNRESET_ADDR);
    reg = readl(HI_ES_TSP_REG_DSS1_UNRESET_ADDR);
    reg |= 0x9;
    writel(reg, HI_ES_TSP_REG_DSS1_UNRESET_ADDR);
    reg = readl(HI_ES_TSP_REG_DSS2_UNRESET_ADDR);
    reg |= 0x9;
    writel(reg, HI_ES_TSP_REG_DSS2_UNRESET_ADDR);
    reg = readl(HI_ES_TSP_REG_DSS3_UNRESET_ADDR);
    reg |= 0x9;
    writel(reg, HI_ES_TSP_REG_DSS3_UNRESET_ADDR);
    return;
}

static inline unsigned int modem_ccore_is_running(void)
{
    u32 reg;

    reg = readl(HI_ES_TSP_SYSCTRL_DSS0_T0_PC);
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS0_T1_PC);
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS0_T2_PC);
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS0_T3_PC);

    reg |= readl(HI_ES_TSP_SYSCTRL_DSS1_T0_PC);
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS1_T1_PC);
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS1_T2_PC);
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS1_T3_PC);
    
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS2_T0_PC);
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS2_T1_PC);
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS2_T2_PC);
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS2_T3_PC);
    
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS3_T0_PC);
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS3_T1_PC);
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS3_T2_PC);
    reg |= readl(HI_ES_TSP_SYSCTRL_DSS3_T3_PC);

    if (reg != 0) {
        return 1;
    }
    return 0;
}
#endif

#ifdef CONFIG_MODEM_SECBOOT_CS
static inline void modem_ccore_unreset(void)
{
    u32 reg;

    /* unreset for dss0-3 */
    reg = readl(HI_CS_TSP_REG_DSS0_UNRESET_ADDR);
    reg |= 0x9;
    writel(reg, HI_CS_TSP_REG_DSS0_UNRESET_ADDR);
    reg = readl(HI_CS_TSP_REG_DSS1_UNRESET_ADDR);
    reg |= 0x9;
    writel(reg, HI_CS_TSP_REG_DSS1_UNRESET_ADDR);
    reg = readl(HI_CS_TSP_REG_DSS2_UNRESET_ADDR);
    reg |= 0x9;
    writel(reg, HI_CS_TSP_REG_DSS2_UNRESET_ADDR);
    return;
}

static inline unsigned int modem_ccore_is_running(void)
{
    u32 reg;

    reg = readl(HI_CS_TSP_SYSCTRL_DSS0_T0_PC);
    reg |= readl(HI_CS_TSP_SYSCTRL_DSS0_T1_PC);
    reg |= readl(HI_CS_TSP_SYSCTRL_DSS0_T2_PC);
    reg |= readl(HI_CS_TSP_SYSCTRL_DSS0_T3_PC);

    reg |= readl(HI_CS_TSP_SYSCTRL_DSS1_T0_PC);
    reg |= readl(HI_CS_TSP_SYSCTRL_DSS1_T1_PC);
    reg |= readl(HI_CS_TSP_SYSCTRL_DSS1_T2_PC);
    reg |= readl(HI_CS_TSP_SYSCTRL_DSS1_T3_PC);
    
    reg |= readl(HI_CS_TSP_SYSCTRL_DSS2_T0_PC);
    reg |= readl(HI_CS_TSP_SYSCTRL_DSS2_T1_PC);
    reg |= readl(HI_CS_TSP_SYSCTRL_DSS2_T2_PC);
    reg |= readl(HI_CS_TSP_SYSCTRL_DSS2_T3_PC);

    if (reg != 0) {
        return 1;
    }
    return 0;
}
#endif

static inline void modem_ccore_reset(void)
{
    int i;
    unsigned int *modem_image_size = NULL;

    if (modem_ccore_is_running()) {
        tloge("ccore is running, can not reset!\n");
        return;
    }
    modem_image_size = hisi_secboot_get_modem_image_size_st();
    if (modem_image_size == NULL) {
        tloge("modem_ccore_reset fail to get modem_image_size.\n");
        return;
    }
    for (i = 0; i < MAX_SOC; i++) {
        modem_image_size[i] = 0;
    }
    g_modem_load.modem_status = 0;
}
#endif