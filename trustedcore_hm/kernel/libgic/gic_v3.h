/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: v3 version gic offset defines
 * Create: 2020-12
 */
#ifndef LIBGIC_GIC_V3_H
#define LIBGIC_GIC_V3_H

#include <gic_common.h>

#define __reg_1(x...)    #x
#define reg(x...)    __reg_1(x)

#if defined(CONFIG_ASCEND_PLATFORM) || defined(CONFIG_KUNPENG_PLATFORM_1620)
#define SIZE_PER_GICR    CONFIG_GICR_PER_SIZE
#else
#define SIZE_PER_GICR    0x20000
#endif
#define GIC_TRY_TIMES    100000
#define SGI_BASE    0x10000

/* GICD registers */
#define GICD_IROUTERn        0x6000
#define GICD_IGRPMODRn        0x0d00

/* GICR registers */
#define GICR_CTLR        0x0000
#define GICR_IIDR        0x0004
#define GICR_TYPER        0x0008
#define GICR_WAKER        0x0014

/* GICR SGI base registers */
#define GICR_IGROUPR0        0x0080
#define GICR_ISENABLER0        0x0100
#define GICR_ICENABLER0        0x0180
#define GICR_ISPENDR0        0x0200
#define GICR_ICPENDR0        0x0280
#define GICR_ISACTIVER0        0x0300
#define GICR_ICACTIVER0        0x0380
#define GICR_IPRIORITYRn    0x0400
#define    GICR_ICFGR0        0x0c00
#define    GICR_ICFGR1        0x0c04
#define GICR_IGRPMODR0        0x0d00
#define GICR_NSACR        0x0e00

#define GICD_EN_ARES        (1 << 4)
#define GICD_CTLR_RWP        (1 << 31)
#define GICD_IROUTE_IRM_BIT    31

#define GICR_CTLR_UWP        (1 << 31)
#define GICR_WAKER_PROC_SLEEP    (1 << 1)
#define GICR_WAKER_CHLDR_SLEEP    (1 << 2)

#define ICC_CTLR_EOIMODE_BIT    1
#define ICC_SRE_EL1_SRE        (1 << 0)

/* MPID */
#define MPIDR_AFF0_SHIFT    0
#define MPIDR_AFF0_MASK        0xff
#define MPIDR_AFF1_SHIFT    8
#define MPIDR_AFF1_MASK        0xff00
#define MPIDR_AFF2_SHIFT    16
#define MPIDR_AFF2_MASK        0xff0000
#define MPIDR_AFF3_SHIFT    32
#define MPIDR_AFF3_MASK        0xff00000000ULL
#define MPIDR_AF012_MASK    0xffffff
#define MPIDR_AFF_MASK        0xff00ffffffULL
#define MPIDR_TO_ROUTE_AFF(mpidr, irm)    (((mpidr) & MPIDR_AFF_MASK) | \
                     ((irm) << GICD_IROUTE_IRM_BIT))
#define MPIDR_MT            (1 << 24)

#endif /* LIBGIC_GIC_V3_H */
