/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: arc platform-related defination
 * Author     : m00475438
 * Create     : 2018/08/11
 */
#ifndef __PAL_INTERRUPT_PLAT_H__
#define __PAL_INTERRUPT_PLAT_H__
#include "soc_irqs.h"

/* define irq number */
#define INTR_HIEPS2AP_ALARM                         420
#define INTR_HIEPS2GIC_ECC                          385
#define INTR_HIEPS2GIC_SM9                          504
#define INTR_HIEPS2GIC_RSA                          384
#define INTR_HIEPS2GIC_RSA2                         108
#define INTR_HIEPS2GIC_RSA3                         153
#define INTR_HIEPS2GIC_SCE                          427
#define INTR_HIEPS2GIC_SCE2                         107

#define PAL_HIEPS2AP_ALARM                          INTR_HIEPS2AP_ALARM

#define PAL_IRQ_KM_ALARM                            IRQ_KM_ALARM
#define PAL_IRQ_SCE                                 INTR_HIEPS2GIC_SCE
#define PAL_IRQ_SCE_ALARM                           IRQ_SCE_ALARM
#define PAL_IRQ_RSA                                 INTR_HIEPS2GIC_RSA
#define PAL_IRQ_RSA_ALARM                           IRQ_RSA_ALARM

#define PAL_IRQ_ECC                                 INTR_HIEPS2GIC_ECC
#define PAL_IRQ_ECC_ALARM                           IRQ_ECC_ALARM
#define PAL_IRQ_TRNG                                IRQ_TRNG
#define PAL_IRQ_TRNG_ALARM                          IRQ_TRNG_ALARM

#define PAL_IRQ_SCE2                                INTR_HIEPS2GIC_SCE2
#define PAL_IRQ_SCE2_ALARM                          IRQ_SCE2_ALARM
#define PAL_IRQ_RSA2                                INTR_HIEPS2GIC_RSA2
#define PAL_IRQ_RSA2_ALARM                          IRQ_RSA2_ALARM
#define PAL_IRQ_RSA3                                INTR_HIEPS2GIC_RSA3
#define PAL_IRQ_RSA3_ALARM                          IRQ_RSA3_ALARM

#define PAL_IRQ_SM9                                 INTR_HIEPS2GIC_SM9
#define PAL_IRQ_SM9_ALARM                           IRQ_SM9_ALARM

void pal_irq_handler(u32 irq_num);
#endif /* __PAL_INTERRUPT_PLAT_H__ */
