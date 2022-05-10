/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: v3 version gic function file
 * Create: 2020-12
 */
#include <config.h>
#include <lib/log.h>
#include <plat/machine/hardware.h>
#include "gic_v3.h"
#include <smp/smp.h>
#include <elfloader.h>
#include <kernel/tee.h>

struct gic_v3_data {
    uint64_t gic_dist_base;
    uint64_t gic_redist_base;
    uint32_t size_per_gicr;
};

static struct gic_v3_data gic;

static bool mt;
static uint64_t cpu_affinity[CONFIG_MAX_NUM_NODES];
static uint64_t gicr[CONFIG_MAX_NUM_NODES];

static inline void write32_dist_reg(uint32_t offset, uint32_t val)
{
    *(uint32_t *)(uintptr_t)(gic.gic_dist_base + offset) = val;
}

static inline uint32_t read32_dist_reg(uint32_t offset)
{
    return *(uint32_t *)(uintptr_t)(gic.gic_dist_base + offset);
}

static inline void write64_dist_reg(uint32_t offset, uint64_t val)
{
    *(uint64_t *)(uintptr_t)(gic.gic_dist_base + offset) = val;
}

static inline void write32_redist_reg(uint32_t offset, uint32_t val)
{
    *(uint32_t *)(uintptr_t)(gicr[get_current_cpu_id()] + offset) = val;
}

static inline uint32_t read32_redist_reg(uint32_t offset)
{
    return *(uint32_t *)(uintptr_t)(gicr[get_current_cpu_id()] + offset);
}

static void gic_wait_for_rwp(void)
{
    int cnt = GIC_TRY_TIMES;    /* try 100ms at most */
    while (read32_dist_reg(GICD_CTLR) & GICD_CTLR_RWP) {
        cnt--;
        if (!cnt) {
            klog(DEBUG_WARNING, "Wait for RWP timeout.\n");
            return;
        }
        /* NOTE: need delay 1us */
    }
}

static void gic_wait_for_uwp(void)
{
    int cnt = GIC_TRY_TIMES;    /* try 100ms at most */
    while (read32_redist_reg(GICR_CTLR) & GICR_CTLR_UWP) {
        cnt--;
        if (!cnt) {
            klog(DEBUG_WARNING, "Wait for UWP timeout.\n");
            return;
        }
        /* NOTE: need delay 1us */
    }
}

/*
 * Each interrupt uses 1 bit.
 * With GICv3, if ARE==1, SGIs and PPIs use GICR_ISENABLER0 and
 * GICR_ICENABLER0 instead of GICD_ISENABLERn and GICD_ICENABLERn.
 * Write 1 to set-enable register to enable the interrupt.
 * Write 1 to clear-enable register do disable the interrupt.
 */
static void gic_set_irq_enable(uint32_t irq, bool enable)
{
    if (irq >= IRQ_SPI_START) { /* SPIs */
        if (enable)
            write32_dist_reg(GICD_ISENABLERn + IRQ_BASE(irq, 1), (uint32_t)BIT(IRQ_BIT(irq, 1)));
        else
            write32_dist_reg(GICD_ICENABLERn + IRQ_BASE(irq, 1), (uint32_t)BIT(IRQ_BIT(irq, 1)));
        gic_wait_for_rwp();
    } else { /* SGIs ~ PPIs */
        if (enable)
            write32_redist_reg(SGI_BASE + GICR_ISENABLER0, (uint32_t)BIT(irq));
        else
            write32_redist_reg(SGI_BASE + GICR_ICENABLER0, (uint32_t)BIT(irq));
        gic_wait_for_uwp();
    }
}

/*
 * Each interrupt uses 1 bit.
 * With GICv3, if ARE==1, SGIs and PPIs use GICR_ISPENDR0 and
 * GICR_ICPENDR0 instead of GICD_ISENABLERn and GICD_ICENABLERn.
 * Write 1 to set-pend register to set pend.
 * Write 1 to clear-pend register to clear pend.
 */
static void gic_set_irq_pend(uint32_t irq, bool pend)
{
    if (irq >= IRQ_SPI_START) { /* SPIs */
        if (pend)
            write32_dist_reg(GICD_ISPENDRn + IRQ_BASE(irq, 1), (uint32_t)BIT(IRQ_BIT(irq, 1)));
        else
            write32_dist_reg(GICD_ICPENDRn + IRQ_BASE(irq, 1), (uint32_t)BIT(IRQ_BIT(irq, 1)));
        gic_wait_for_rwp();
    } else { /* SGIs ~ PPIs */
        if (pend)
            write32_redist_reg(SGI_BASE + GICR_ISPENDR0, (uint32_t)BIT(irq));
        else
            write32_redist_reg(SGI_BASE + GICR_ICPENDR0, (uint32_t)BIT(irq));
        gic_wait_for_uwp();
    }
}

/*
 * Each interrupt uses 8 bit.
 * With GICv3, if ARE==1, SGIs and PPIs use GICR_IPRIORITYRn.
 */
static void gic_set_irq_priority(uint32_t irq, uint8_t prio)
{
    uint32_t irq_base = IRQ_BASE(irq, 8);
    uint32_t irq_bit = IRQ_BIT(irq, 8);
    uint32_t new_prio;
    uint32_t old_prio;

    if (irq >= IRQ_SPECIAL_START) {
        klog(DEBUG_WARNING, "invalid irq no %u\n", irq);
        return;
    }

    if (irq >= IRQ_SPI_START)
        old_prio = read32_dist_reg(GICD_IPRIORITYRn + irq_base);
    else
        old_prio = read32_redist_reg(SGI_BASE + GICR_IPRIORITYRn + irq_base);

    /* clear old priority */
    new_prio = old_prio & ~(INT_PRIO_MASK << irq_bit);
    /* set new priorty */
    new_prio |= ((uint32_t)prio << irq_bit);
    if (irq >= IRQ_SPI_START) {
        write32_dist_reg(GICD_IPRIORITYRn + irq_base, new_prio);
        gic_wait_for_rwp();
    } else {
        write32_redist_reg(SGI_BASE + GICR_IPRIORITYRn + irq_base, new_prio);
        gic_wait_for_uwp();
    }

    klog(DEBUG_LOG,
         "[IRQ DEBUG] hwirq:%u set priority old:%x, new:%x\n",
         irq, (old_prio >> irq_bit) & INT_PRIO_MASK, prio);
}

static void gic_mask_interrupt(uint32_t irq)
{
    gic_set_irq_enable(irq, false);
}

static void gic_unmask_interrupt(uint32_t irq)
{
    gic_set_irq_enable(irq, true);
}

/*
 * Each interrupt uses 1 bit.
 * With GICv3, if ARE==1, SGIs and PPIs use GICR_IGROUPR0 instead
 * of GICD_IGROUPn.
 * If group == 0, the interrupt is secure group1;
 * if group == 1, the interrupt is non-secure group1.
 */
static void gic_set_irq_group(uint32_t irq, uint32_t group)
{
    uint32_t irq_base = IRQ_BASE(irq, 1);
    uint32_t irq_bit = IRQ_BIT(irq, 1);
    uint32_t bit_mask = (uint32_t)BIT(irq_bit);
    uint32_t old_grp, new_grp;
    uint32_t old_mod, new_mod;

    if (irq >= IRQ_SPECIAL_START) {
        klog(DEBUG_WARNING, "invalid irq no %u\n", irq);
        return;
    }

    if (irq >= IRQ_SPI_START) {
        old_grp = read32_dist_reg(GICD_IGROUPn + irq_base);
        old_mod = read32_dist_reg(GICD_IGRPMODRn + irq_base);
    } else {
        old_grp = read32_redist_reg(SGI_BASE + GICR_IGROUPR0);
        old_mod = read32_redist_reg(SGI_BASE + GICR_IGRPMODR0);
    }
    if (group) {
        new_grp = old_grp | bit_mask;
        new_mod = old_mod & ~bit_mask;
    } else {
        new_grp = old_grp & ~bit_mask;
        new_mod = old_mod | bit_mask;
    }
    if (irq >= IRQ_SPI_START) {
        write32_dist_reg(GICD_IGROUPn + irq_base, new_grp);
        write32_dist_reg(GICD_IGRPMODRn + irq_base, new_mod);
        gic_wait_for_rwp();
    } else {
        write32_redist_reg(SGI_BASE + GICR_IGROUPR0, new_grp);
        write32_redist_reg(SGI_BASE + GICR_IGRPMODR0, new_mod);
        gic_wait_for_uwp();
    }
}

#define IRQ_NUM_ICFGR_HAS 16
#define BYTES_PER_32BIT 4
#define IRQ_ICFGR_PROPERTY_BITS 2
static void gic_trigger_set(uint32_t irq, uint32_t flags)
{
    uint32_t val;
    uint32_t offset;

     /* SGI are always treated as edge-triggered, cannot set */
    if ((irq < IRQ_SPI_START) || (irq >= MAX_IRQ) ||
        ((flags != IRQ_LEVEL_MODE) && (flags != IRQ_EDGE_MODE))) {
        klog(DEBUG_LOG, "invalid param:%u flags:0x%x\n", irq, flags);
        return;
    }

    /*
     * set trigger type
     * each GICD_ICFGRn has 32bit, express 16 irq
     */
    val = read32_dist_reg(GICD_ICFGRn + (irq / IRQ_NUM_ICFGR_HAS) * BYTES_PER_32BIT);

    /*
     * each irq has two bits(bits[2x+1, 2x]) to indicate whether edge-triggered or level-sensitive
     * bits[2x] is reserved, bits[2x+1] can set
     */
    offset = (irq % IRQ_NUM_ICFGR_HAS) * IRQ_ICFGR_PROPERTY_BITS;
    if (flags == IRQ_EDGE_MODE)
        val |= (0x2 << offset); /* set to 1 (0bx1) when edge-triggered */
    else
        val &= ~(0x2 << offset); /* set to 0 (0bx0) level-sensitive */

    write32_dist_reg((GICD_ICFGRn + (irq / IRQ_NUM_ICFGR_HAS) * BYTES_PER_32BIT), val);
    gic_wait_for_rwp();
}

/*
 * Each interrupt uses 64 bit.
 * Each 64-bit stand for one mpidr.
 */
static int gic_set_irq_target(uint32_t irq, uint64_t target_cpu_id)
{
    if (irq >= IRQ_SPI_START && irq < IRQ_SPECIAL_START) {
#ifdef CONFIG_IRQ_MIGRATE_ENABLE
        uint64_t mpidr = cpu_affinity[target_cpu_id];
#else
        uint64_t mpidr = get_mpidr_el1();
        (void)target_cpu_id;
#endif
        uint32_t irq_base = IRQ_BASE(irq, 1);
        uint32_t irq_bit = IRQ_BIT(irq, 1);
        uint32_t is_enable = read32_dist_reg(GICD_ISENABLERn + irq_base) & (1 << irq_bit);
        if (is_enable)
            gic_mask_interrupt(irq);
        /* set irq route */
        irq_base = IRQ_BASE(irq, 64);
        write64_dist_reg(GICD_IROUTERn + irq_base, MPIDR_TO_ROUTE_AFF(mpidr, 0));
        if (is_enable)
            gic_unmask_interrupt(irq);
        gic_wait_for_rwp();
        return E_EX_OK;
    } else {
        klog(DEBUG_LOG, "Invalid hwirq:%u\n", irq);

        return E_EX_INVAL;
    }
}

/*
 * [63:56] Reserved.
 * [55:48] AFF3
 * [47:44] RS: Controls which group of 16 values is represented by the TargetList field.
 * [43:41] Reserved.
 * [40] IRM, 0: route to Aff3.Aff2.Aff1.<target list>; 1: route to all cpus, excluding "self".
 * [39:32] AFF2
 * [31:28] Reserved.
 * [27:24] INTID
 * [23:16] AFF1
 * [15:0] Target List. The set of PEs for which SGI interrupts will be generated. Each bit corresponds to the
 * PE within a cluster with an Affinity 0 value equal to the bit number.
 */
static void gic_send_sgi(uint32_t irq, uint32_t target_list)
{
    (void)irq;
    (void)target_list;
#if !defined(CONFIG_KUNPENG_PLATFORM_1620) && !defined(CONFIG_ASCEND_PLATFORM)
    uint32_t i;

    for (i = 0; i < (uint32_t)get_cpu_nr(); i++) {
        if ((1 << i) & target_list) {
            uint64_t sgi1r;
            uint64_t aff = cpu_affinity[i];
            if (mt) {
                sgi1r = ((aff >> 32) << 48) |          /* aff3 */
                        (((aff >> 16) & 0xff) << 32) | /* aff2 */
                        (((aff >> 8) & 0xff) << 16) |  /* aff1 */
                        1 |                            /* if mt== true, targetlist is always 1 */
                        ((uint64_t)irq << 24);         /* irq */
            } else {
                sgi1r = ((aff >> 32) << 48) |          /* aff3 */
                        (((aff >> 16) & 0xff) << 32) | /* aff2 */
                        (((aff >> 8) & 0xff) << 16) |  /* aff1 */
                        (1 << (i % 4)) |               /* targetlist */
                        ((uint64_t)irq << 24);         /* irq */
            }
            set_icc_sgi1r_el1(sgi1r);
            gic_isb();
        }
    }
#endif
}


/* send a SGI to cpu(s) */
static int gic_irq_trigger(uint32_t irq, uint32_t mode, uint32_t cpu)
{
    switch (cpu) {
    case SRE_CPU0:
        /* send sgi to cpu0 */
        gic_send_sgi(irq, 1);
        break;
    case SRE_CPU1:
    case SRE_CPU2:
    case SRE_CPU3:
        /* send sgi to all cpus */
        gic_send_sgi(irq, ALL_CPU_MASK);
        break;
    default:
        klog(DEBUG_LOG,
             "[IRQ DEBUG] trigger irq[%u] on cpu[%u] in mode[%u] failed\n", irq, cpu, mode);
        return E_EX_INVAL;
    }
    klog(DEBUG_LOG, "[IRQ DEBUG] trigger irq[%u] on cpu[%u] in mode[%u]\n", irq,
         cpu, mode);
    return E_EX_OK;
}


/*
 * [12:10] CPUID
 * [9:0] Interrupt ID
 */
static uint32_t gic_read_interrupt(void)
{
    unsigned long iar;

    iar = get_icc_iar1_el1();
    gic_dsb(sy);

    /* Interrupt numbers ID1020-ID1023 are reserved for special purposes */
    if (iar >= IRQ_SPECIAL_START) {
        set_icc_eoir1_el1(iar);
        gic_isb();
        return IRQ_SPURIOUS;
    } else {
        return (uint32_t)iar;
    }
}

/*
 * [31:24] Reserved.
 * [23:0] The INTID from the corresponding ICC_IAR1_EL1 access.
 */
static void gic_end_interrupt(uint32_t irq)
{
    set_icc_eoir1_el1((unsigned long)irq);
    gic_isb();
}

static void gic_sys_reg_init(void)
{
    unsigned long sre, ctlr;

    /*
     * Enable SRE
     * bit[31:3]: reserved
     * bit[2]: Disable IRQ bypass.
     * bit[1]: Disable FIQ bypass.
     * bit[0]: System Register Enable.
     */
    sre = get_icc_sre_el1();
    sre |= ICC_SRE_EL1_SRE;
    set_icc_sre_el1(sre);
    gic_isb();
    /* check SRE */
    sre = get_icc_sre_el1();
    klog(DEBUG_LOG, "CPU%d SRE:%lx\n", (int)get_current_cpu_id(), sre);
    if (!(sre & ICC_SRE_EL1_SRE))
        klog(DEBUG_WARNING, "Cannot enable SRE.\n");

    /*
     * set EOIMode=1
     * 0: provide both priority drop and interrupt deactivation functionality.
     * 1: provide priority drop functionality only.
     */
    ctlr = get_icc_ctlr_el1();
    ctlr &= ~(1 << ICC_CTLR_EOIMODE_BIT);
    set_icc_ctlr_el1(ctlr);
    gic_isb();
    /* check EOIMode */
    ctlr = get_icc_ctlr_el1();
    klog(DEBUG_LOG, "CPU%d CTLR:%lx\n", (int)get_current_cpu_id(), ctlr);
    if (ctlr & (1 << ICC_CTLR_EOIMODE_BIT))
        klog(DEBUG_WARNING, "Cannot set EOIMode to 1\n");
}

static void gic_enable_gicr(void)
{
    int cnt = GIC_TRY_TIMES;    /* try 100ms at most */
    uint32_t waker = read32_redist_reg(GICR_WAKER);
    /* This GICR has already wake up */
    if (!(waker & GICR_WAKER_CHLDR_SLEEP))
        return;

    waker &= ~GICR_WAKER_PROC_SLEEP;
    write32_redist_reg(GICR_WAKER, waker);
    while (read32_redist_reg(GICR_WAKER) & GICR_WAKER_CHLDR_SLEEP) {
        cnt--;
        if (!cnt) {
            klog(DEBUG_WARNING, "Wait for GICR wake up timeout.\n");
            return;
        }
        /* NOTE: need delay 1us */
    }
}

BOOT_CODE static void gicr_init(void)
{
    uint64_t i;
    uint64_t mpidr = get_mpidr_el1();
    int cpu = (int)get_current_cpu_id();

    /* set gicr base address of each cpu */
    for (i = 0; i < (uint64_t)get_cpu_nr(); i++) {
        /* read high 32-bits */
        uint64_t base = gic.gic_redist_base + i * gic.size_per_gicr;
        /* read high 32-bits */
        uint32_t typer = *(uint32_t *)(uintptr_t)(base + GICR_TYPER + 4);
        uint64_t aff = cpu_affinity[cpu];
        aff = ((aff & MPIDR_AFF3_MASK) >> 8) |
              (aff & (MPIDR_AF012_MASK));
        if (typer == (uint32_t)aff) {
            gicr[cpu] = base;
            break;
        }
    }
    if (!gicr[cpu]) {
        panic("Can't find GICR for CPU%d mpidr:%lx\n",
              cpu, (unsigned long)mpidr);
    } else {
        klog(DEBUG_LOG, "CPU%d mpidr:%lx uses GICR:%lx\n", cpu,
             (unsigned long)mpidr, (unsigned long)gicr[cpu]);
        gic_enable_gicr();
    }
}

static void gic_distributor_init(void)
{
    uint32_t ctlr = read32_dist_reg(GICD_CTLR);
    /*
     * bit[4]: ARE_S
     * bit[2]: EnableGrp1S
     * bit[0]: EnableGrp0
     */
    write32_dist_reg(GICD_CTLR, GICD_EN_ARES | GICD_EN_GRP1S | GICD_EN_GRP0 | ctlr);
    gic_wait_for_rwp();
}

BOOT_CODE static void gic_cpu_init(void)
{
    uint64_t mpidr = get_mpidr_el1();
    /* MT decides how to send a sgi */
    if (mpidr & MPIDR_MT)
        mt = true;
    else
        mt = false;

    /* set affinity of each cpu */
    cpu_affinity[get_current_cpu_id()] = mpidr & MPIDR_AFF_MASK;

    gicr_init();
    gic_sys_reg_init();
}

BOOT_CODE static void gic_init(void)
{
    gic_distributor_init();
}

BOOT_CODE static void gic_cpu_iface_init(void)
{
    gic_cpu_init();
}

/* Used for CPU resume after CPU suspend */
static void gic_resume(void)
{
    gic_distributor_init();
}

static void gic_map_device(void *data)
{
    struct gic_config_t *config = data;
    kernel_frame_t frame = {0, 0, 0, true};
    uint32_t i;
    uint64_t size;
    kaddr_t kaddr = GIC3_KADDR_BASE;

    gic.gic_dist_base = kaddr;

    /* map dist's io space */
    frame.paddr = config->v3.dist.start;
    size = config->v3.dist.end - config->v3.dist.start;
    frame.kaddr = kaddr;
    frame.nr_pages = (int32_t)(size / PAGE_SIZE);
    map_kernel_device_frames(&frame, 1);

    kaddr += size;
    gic.gic_redist_base = kaddr;

    /* save redist's stride */
    gic.size_per_gicr = config->v3.redist_stride;

    /* map redist's io space */
    for (i = 0; i < config->v3.redist_num; i++) {
        frame.paddr = config->v3.redist[i].start;
        size = config->v3.redist[i].end - config->v3.redist[i].start;
        frame.kaddr = kaddr;
        frame.nr_pages = (int32_t)(size / PAGE_SIZE);
        map_kernel_device_frames(&frame, 1);
        kaddr += size;
    }
}

struct gic_interface gic3_interface = {
    .__gic_set_irq_pend = gic_set_irq_pend,
    .__gic_set_irq_priority = gic_set_irq_priority,
    .__gic_set_irq_group = gic_set_irq_group,
    .__gic_set_irq_target = gic_set_irq_target,
    .__gic_set_exclusive_irq_target = gic_set_irq_target,
    .__gic_resume = gic_resume,
    .__gic_irq_trigger = gic_irq_trigger,
    .__gic_mask_interrupt = gic_mask_interrupt,
    .__gic_unmask_interrupt = gic_unmask_interrupt,
    .__gic_read_interrupt = gic_read_interrupt,
    .__gic_end_interrupt = gic_end_interrupt,
    .__gic_send_sgi = gic_send_sgi,
    .__gic_map_device = gic_map_device,
    .__gic_init = gic_init,
    .__gic_cpu_iface_init = gic_cpu_iface_init,
    .ivt = hm_ivt_gic3,
    .__gic_trigger_set = gic_trigger_set,
};

device_descriptor_t gic3 = {
    .name = "gic_v3",
    .interface = &gic3_interface,
};
