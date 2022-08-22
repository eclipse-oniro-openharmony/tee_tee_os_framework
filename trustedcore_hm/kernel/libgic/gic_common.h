/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: gic common defines
 * Create: 2020-12
 */
#ifndef LIBGIC_GIC_COMMON_H
#define LIBGIC_GIC_COMMON_H

#define GICC_ALIASED_BP   0x1C
#define GICC_BP           0x8
#define GICC_PRIMASK      0x4
#define GICD_CTR         0x4
#define GICD_CTLR        0x000
#define GICD_TYPER        0x004
#define GICD_IIDR        0x008
#define GICD_IGROUPn        0x080
#define GICD_ISENABLERn        0x100
#define GICD_ICENABLERn        0x180
#define GICD_ISPENDRn        0x200
#define GICD_ICPENDRn        0x280
#define GICD_ISACTIVERn        0x300
#define GICD_ICACTIVERn        0x380
#define GICD_IPRIORITYRn    0X400
#define GICD_ITARGETSRn        0x800
#define GICD_ICFGRn        0xc00
#define GICD_SGIR        0xf00
#define GICD_CPENDSGIRn        0xf10
#define GICD_SPENDSGIRn        0xf20

#define GICD_EN_GRP0        (1 << 0)
#define GICD_EN_GRP1        (1 << 1)
#define GICD_EN_GRP1S        (1 << 2)

#define IRQ_BASE(irq, bit_nr)    ((((irq) * (bit_nr)) / 8) & ~3U)    /* 4-bytes aligned */
#define IRQ_BIT(irq, bit_nr)    (((irq) * (bit_nr)) % 32)
#define IRQ_LEVEL_MODE        0
#define IRQ_EDGE_MODE        1

#define NR_IRQS_MASK        0x1f
#define IRQ_MASK        0x3ff
#define IRQ_SPURIOUS        1023
#define IRQ_SPECIAL_START    1020
#define IRQ_SPI_START    32
#define IRQ_SGI_END      15

#define GICD_INT_CLR_ENABLE    0xffffffff
#define GICD_INT_CLR_PEND    0xffffffff

#define INT_DEFAULT_PMR        0xf0
#define INT_DEFAULT_BPR        3
#if defined(CONFIG_AARCH32_MONITOR)
#define INT_DEFAULT_PRIO    0x80808080
#define INT_DEFAULT_GRP        0xffffffff
#else
#define INT_DEFAULT_PRIO    0
#define INT_DEFAULT_GRP        0
#endif
#define INT_PRIO_MASK        0xff
#define INT_DEFAULT_TAR        (BIT(0) << 24 | \
                 BIT(0) << 16 | \
                 BIT(0) << 8  | \
                 BIT(0))
#define INT_DEFAULT_CFG        0x55555555
#define ALL_CPU_MASK        0xff

#define SRE_CPU0        0
#define SRE_CPU1        1
#define SRE_CPU2        2
#define SRE_CPU3        3

#define gic_isb()    asm volatile("isb" : : : "memory")
#define gic_dsb(opt)    asm volatile("dsb " #opt : : : "memory")

#endif /* LIBGIC_GIC_COMMON_H */
