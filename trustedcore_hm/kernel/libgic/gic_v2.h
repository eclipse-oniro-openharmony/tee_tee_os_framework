/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: v2 version gic offset defines
 * Create: 2020-12
 */
#ifndef LIBGIC_GIC_V2_H
#define LIBGIC_GIC_V2_H

#include <types.h>
#include <gic_common.h>

#define GICC_CTLR        0x000
#define GICC_PMR        0x004
#define GICC_BPR        0x008
#define GICC_IAR        0x00c
#define GICC_EOIR        0x010
#define GICC_RPR        0x014
#define GICC_HPPIR        0x018
#define GICC_ABPR        0x01c
#define GICC_AIAR        0x020
#define GICC_AEOIR        0x024
#define GICC_AHPPIR        0x028

#define GICC_EN_GRP0        (1 << 0)
#define GICC_EN_GRP1        (1 << 1)
#define GICC_EN_FIQ        (1 << 3)

/* Shift positions for GICD_SGIR register */
#define GICD_SGIR_SGIINTID_SHIFT        0
#define GICD_SGIR_NSATT_SHIFT            15
#define GICD_SGIR_CPUTARGETLIST_SHIFT        16
#define GICD_SGIR_TARGETLISTFILTER_SHIFT    24

#define GICC_EOIR_CPUID_SHIFT        10

#define INT_TARGET_MASK        0xff

#endif /* LIBGIC_GIC_V2_H */
