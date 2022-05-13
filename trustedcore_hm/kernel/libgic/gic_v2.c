/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: v2 version gic function file
 * Create: 2020-12
 */
#include <config.h>
#include <lib/log.h>
#include <plat/machine/hardware.h>
#include "gic_v2.h"
#include <smp/smp.h>

struct gic_v2_data {
    uint64_t gic_dist_base;
    uint64_t gic_cpu_base;
    uint32_t nr_irqs;
};

static struct gic_v2_data gic = {
    .gic_dist_base = GIC2_DISTRIBUTOR_KADDR,
    .gic_cpu_base = GIC2_CONTROLLER_KADDR,
    .nr_irqs = 0,
};

#ifdef CONFIG_AARCH32_SUSPEND_RESUME
#define GICD_COUNT    4
#define SAVED_NUM     128
#define PRIORITY_NUM  8
#define INVALID_VAL   0xffffffff
struct gic_control {
    uint32_t saved_cfg[SAVED_NUM];
    uint32_t saved_cpu_primask_cfg;
    uint32_t saved_gic_cpu_ctrl_cfg;
    uint32_t saved_gic_cpu_bpr_cfg;  /* binary point reg */
    uint32_t saved_gic_cpu_abpr_cfg; /* aliased binary point reg */
    uint32_t spi_lines;
} gic_ctrl_suspend_resume;
#endif

static void gic_map_device(void *data);

/*
 * reg is no more than 0x028
 * so there is no overflow
 */
static void write32_cpu_reg(uint32_t reg, uint32_t val)
{
    *(volatile uint32_t *)(uintptr_t)(gic.gic_cpu_base + reg) = val;
}

/*
 * reg is no more than 0x028
 * so there is no overflow
 */
static uint32_t read32_cpu_reg(uint32_t reg)
{
    return *(volatile uint32_t *)(uintptr_t)(gic.gic_cpu_base + reg);
}

#ifdef CONFIG_AARCH32_SUSPEND_RESUME
static void writel(uint32_t val, uint64_t addr)
{
    asm volatile("dsb");
    (*(volatile uint32_t *)(uintptr_t)(addr)) = (val);
    asm volatile("dsb");
}
static uint32_t readl(uint64_t addr)
{
    asm volatile("dsb");
    return (*(volatile uint32_t *)(uintptr_t)(addr));
}
#endif

/*
 * reg is no more than 0x028
 * so there is no overflow
 */
static void write32_dist_reg(uint32_t reg, uint32_t val)
{
    *(uint32_t *)(uintptr_t)(gic.gic_dist_base + reg) = val;
}

/*
 * reg is no more than 0x028
 * so there is no overflow
 */
static uint32_t read32_dist_reg(uint32_t reg)
{
    return *(uint32_t *)(uintptr_t)(gic.gic_dist_base + reg);
}

/*
 * Each interrupt uses 1 bit.
 * Write 1 to GICD_ISENABLERn to enable the interrupt.
 * Write 0 to GICD_ICENABLERn do disable the interrupt.
 */
static void gic_set_irq_enable(uint32_t irq, bool enable)
{
    if (enable)
        write32_dist_reg(GICD_ISENABLERn + IRQ_BASE(irq, 1),
                         (uint32_t)BIT(IRQ_BIT(irq, 1)));
    else
        write32_dist_reg(GICD_ICENABLERn + IRQ_BASE(irq, 1),
                         (uint32_t)BIT(IRQ_BIT(irq, 1)));
    gic_dsb(sy);
}

/*
 * Each interrupt uses 2 bit
 * bit 0: 0, Corresponding interrupt is handled using the N-N model.
 *       1, Corresponding interrupt is handled using the 1-N model.
 * bit 1: 0, Corresponding interrupt is level-sensitive.
 *       1, Corresponding interrupt is edge-triggered.
 */
static uint32_t gic_get_irq_cfg(uint32_t irq)
{
    uint32_t cfg = read32_dist_reg(GICD_ICFGRn + IRQ_BASE(irq, 2));

    return (cfg >> IRQ_BIT(irq, 2)) & 3;
}

/*
 * Each interrupt uses 1 bit.
 * Write 1 to GICD_ISPENDRn to trigger the interrupt.
 * Write 0 to GICD_ICPENDRn do clear the interrupt.
 */
static void gic_set_irq_pend(uint32_t irq, bool pend)
{
    if (pend)
        write32_dist_reg(GICD_ISPENDRn + IRQ_BASE(irq, 1),
                         (uint32_t)BIT(IRQ_BIT(irq, 1)));
    else
        write32_dist_reg(GICD_ICPENDRn + IRQ_BASE(irq, 1),
                         (uint32_t)BIT(IRQ_BIT(irq, 1)));
    gic_dsb(sy);
}

/*
 * Each interrupt uses 8 bit.
 */
static void gic_set_irq_priority(uint32_t irq, uint8_t prio)
{
    uint32_t irq_base = IRQ_BASE(irq, 8);
    uint32_t irq_bit = IRQ_BIT(irq, 8);
    uint32_t new_prio;
    uint32_t old_prio = read32_dist_reg(GICD_IPRIORITYRn + irq_base);

    /* clear old priority */
    new_prio = old_prio & ~(INT_PRIO_MASK << irq_bit);
    /* set new priorty */
    new_prio |= ((uint32_t)prio << irq_bit);
    write32_dist_reg(GICD_IPRIORITYRn + irq_base, new_prio);
    gic_dsb(sy);

    klog(DEBUG_LOG,
         "[IRQ DEBUG] hwirq:%u set priority old:%x, new:%x\n",
         irq, (old_prio >> irq_bit) & INT_PRIO_MASK, prio);
}

/*
 * NOTE: currently gic setup use GICv2 configuration, need add GICv3 support.
 * Each interrupt uses 1 bit.
 * 0, The corresponding interrupt is Group 0.
 * 1, The corresponding interrupt is Group 1.
 */
static void gic_set_irq_group(uint32_t irq, uint32_t group)
{
    uint32_t irq_base = IRQ_BASE(irq, 1);
    uint32_t irq_bit = IRQ_BIT(irq, 1);
    uint32_t bit_mask = (uint32_t)BIT(irq_bit);
    uint32_t old_grp = read32_dist_reg(GICD_IGROUPn + irq_base);

    if (irq >= IRQ_SPECIAL_START) {
        klog(DEBUG_WARNING, "invalid irq no %u\n", irq);
        return;
    }

    if (group)
        write32_dist_reg(GICD_IGROUPn + irq_base, old_grp | bit_mask);
    else
        write32_dist_reg(GICD_IGROUPn + irq_base, old_grp & ~bit_mask);
    gic_dsb(sy);
}

static void gic_trigger_set(uint32_t irq, uint32_t flags)
{
    (void)irq;
    (void)flags;
}

/*
 * seattle, portland and austin:
 *      CLUSTER_ID  CPU_ID  GIC_CPU_Interface
 * A53      0        0-3     0-3
 * A53      0        4-7     4-7
 */
static inline uint32_t os_get_core_gic_interface(void)
{
    unsigned long gic_core_interface = get_mpidr_el1();

    return (gic_core_interface & 0xFF) + ((gic_core_interface & 0xFF00) >> 6);
}

/*
 * Each interrupt uses 8 bit.
 * Each bit stand for one cpu.
 */
static int gic_set_irq_target_core(uint32_t irq, uint32_t core_gic_interface)
{
    if (irq > IRQ_SGI_END && irq < IRQ_SPECIAL_START) {
        uint32_t irq_base = IRQ_BASE(irq, 8);
        uint32_t irq_bit = IRQ_BIT(irq, 8);
        uint32_t target_mask = (uint32_t)BIT(core_gic_interface);
        uint32_t old_target = read32_dist_reg(GICD_ITARGETSRn + irq_base);
        uint32_t new_target;

        klog(DEBUG_LOG, "[IRQ DEBUG] core_gic_interface: %x\n", core_gic_interface);

        /* set irq target */
        target_mask <<= irq_bit;
        /* clear old target */
        new_target = ~(0xffu << irq_bit) & old_target;
        /* set new target */
        new_target |= target_mask;
        write32_dist_reg(GICD_ITARGETSRn + irq_base, new_target);
        gic_dsb(sy);

        klog(DEBUG_LOG,
             "[IRQ DEBUG] set irq target cpu oldvalue = %x, newvalue = %x\n",
             (old_target >> irq_bit) & INT_TARGET_MASK,
             (new_target >> irq_bit) & INT_TARGET_MASK);

        return E_EX_OK;
    } else {
        klog(DEBUG_LOG, "invalid IRQ num %u\n", irq);

        return E_EX_INVAL;
    }
}

static int gic_set_irq_target(uint32_t irq, uint64_t target_cpu_id)
{
    uint32_t core_gic_interface;
    (void)target_cpu_id;

#ifdef CONFIG_ENABLE_TEESMP
    /*
     * If cpu 0 is off, we need to migrate the irq to the next cpu that is on.
     * We have spi notify to pull cpu from non-secure world that actually
     * handles the irq.
     */
    core_gic_interface = target_cpu_id;
#else
    core_gic_interface = os_get_core_gic_interface();
#endif

    return gic_set_irq_target_core(irq, core_gic_interface);
}

/*
 * Attention: Only used for IRQ with determinded destination target.
 * no backup response CPU(s) will be reserved for this irq if it's target cpu was offline.
 */
static int gic_set_exclusive_irq_target(uint32_t irq, uint64_t target_cpu_id)
{
    return gic_set_irq_target_core(irq, target_cpu_id);
}

/* send a SGI to cpu */
static int gic_irq_trigger(uint32_t irq, uint32_t mode, uint32_t cpu)
{
    uint32_t sgir;
    switch (cpu) {
    case SRE_CPU0:
        sgir = ((uint32_t)BIT(os_get_core_gic_interface()) <<
            GICD_SGIR_CPUTARGETLIST_SHIFT) |
               (mode << GICD_SGIR_NSATT_SHIFT) |
               (irq << GICD_SGIR_SGIINTID_SHIFT);
        write32_dist_reg(GICD_SGIR, sgir);
        break;
    case SRE_CPU1:
    case SRE_CPU2:
    case SRE_CPU3:
        sgir = (ALL_CPU_MASK << GICD_SGIR_CPUTARGETLIST_SHIFT) |
               (mode << GICD_SGIR_NSATT_SHIFT) |
               (irq << GICD_SGIR_SGIINTID_SHIFT);
        write32_dist_reg(GICD_SGIR, sgir);
        break;
    default:
        klog(DEBUG_LOG,
             "[IRQ DEBUG] trigger irq[%u] on cpu[%u] in mode[%u] failed\n", irq, cpu, mode);

        return E_EX_INVAL;
    }
    gic_dsb(sy);

    klog(DEBUG_LOG, "[IRQ DEBUG] trigger irq[%u] on cpu[%u] in mode[%u]\n", irq,
         cpu, mode);

    return E_EX_OK;
}

static void gic_send_sgi(uint32_t irq, uint32_t target_list)
{
    uint32_t sgir = (target_list << GICD_SGIR_CPUTARGETLIST_SHIFT) |
            (irq << GICD_SGIR_SGIINTID_SHIFT);
    write32_dist_reg(GICD_SGIR, sgir);
    gic_dsb(sy);
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
 * [12:10] CPUID
 * [9:0] Interrupt ID
 */
static uint32_t gic_read_interrupt(void)
{
    uint32_t iar = read32_cpu_reg(GICC_IAR) & IRQ_MASK;
    /*
     * Interrupt numbers ID1020-ID1023 are reserved for special purposes, see Special interrupt numbers on
     * page 3-41.
     */
    if (iar >= IRQ_SPECIAL_START) {
        write32_cpu_reg(GICC_EOIR, iar);
        gic_dsb(sy);
        return IRQ_SPURIOUS;
    } else {
        return iar;
    }
}

/*
 * [31:13] Reserved.
 * [12:10] CPUID: On a multiprocessor implementation, if the write refers to an SGI, this field contains
 * the CPUID value from the corresponding GICC_IAR access.
 * In all other cases this field SBZ.
 * [9:0] EOIINTID: The Interrupt ID value from the corresponding GICC_IAR access.
 */
static void gic_end_interrupt(uint32_t irq)
{
    uint32_t iar = irq;

    /* SGIs */
    if (irq < 16)
        iar = ((uint32_t)BIT(get_current_cpu_id()) << GICC_EOIR_CPUID_SHIFT) | irq;
    /* edge trigger mode */
    if ((gic_get_irq_cfg(irq) >> 1) == IRQ_EDGE_MODE)
        gic_set_irq_pend(irq, false);

    write32_cpu_reg(GICC_EOIR, iar);
    gic_dsb(sy);
}

#if defined (CONFIG_AARCH32_MONITOR)
static void gic_config_sgi_ppi(void)
{
    int i;

    /*
     * disable and clear interrupts
     * set interrupts default group
     */
    write32_dist_reg(GICD_ICENABLERn, GICD_INT_CLR_ENABLE);
    write32_dist_reg(GICD_ICPENDRn, GICD_INT_CLR_PEND);
    write32_dist_reg(GICD_IGROUPn, INT_DEFAULT_GRP);

    /* set interrupts' priority */
    for (i = 0; i < 32; i += 4)
        write32_dist_reg(GICD_IPRIORITYRn + i, INT_DEFAULT_PRIO);
}

static void gic_config_irqs(uint32_t nr_irqs)
{
    int i;

    gic_config_sgi_ppi();

    /*
     * disable and clear interrupts
     * set interrupts default group
     */
    for (i = 32; i < (int)nr_irqs; i += 32) {
        write32_dist_reg(GICD_ICENABLERn + i / 8, GICD_INT_CLR_ENABLE);
        write32_dist_reg(GICD_ICPENDRn + i / 8, GICD_INT_CLR_PEND);
        write32_dist_reg(GICD_IGROUPn + i / 8, INT_DEFAULT_GRP);
    }

    /* set interrupts' default priority and affinity */
    for (i = 32; i < (int)nr_irqs; i += 4) {
        write32_dist_reg(GICD_IPRIORITYRn + i, INT_DEFAULT_PRIO);
        write32_dist_reg(GICD_ITARGETSRn + i, INT_DEFAULT_TAR);
    }

    /* set SPIs' to 1-N and level-triggered */
    for (i = 32; i < (int)nr_irqs; i += 16)
        write32_dist_reg(GICD_ICFGRn + i / 4, INT_DEFAULT_CFG);
}
#endif

static void gic_distributor_init(void)
{
    uint32_t type = read32_dist_reg(GICD_TYPER);
    gic.nr_irqs = ((type & NR_IRQS_MASK) + 1) * 32;

#if defined(CONFIG_AARCH32_MONITOR)
    /* disable GICD */
    write32_dist_reg(GICD_CTLR, 0);

    gic_config_irqs(gic.nr_irqs);
    write32_dist_reg(GICD_CTLR, GICD_EN_GRP0 | GICD_EN_GRP1);
#else
    /*
     * enable the gic distributor
     *   EN_NONSECURE 1
     *   EN_SECURE    1
     */
    write32_dist_reg(GICD_CTLR, GICD_EN_GRP1 | GICD_EN_GRP0);
#endif
    gic_dsb(sy);
}

BOOT_CODE static void gic_cpu_init(void)
{
    /*
     * enable the gic cpu interface
     *   FIQEn    1
     *   AckCtl   0
     *   EnableNS 1
     *   EnableS  1
     */
#ifdef CONFIG_AARCH32_MONITOR
    write32_cpu_reg(GICC_PMR, INT_DEFAULT_PMR);
#endif
    write32_cpu_reg(GICC_CTLR, GICC_EN_FIQ | GICC_EN_GRP1 | GICC_EN_GRP0);
    gic_dsb(sy);
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

#ifdef CONFIG_AARCH32_SUSPEND_RESUME
void gic_cpu_suspend(void);
void gic_cpu_resume(void);
void gic_cpu_suspend(void)
{
    uint32_t i, ret, temp, cnt;
    uint32_t *p_saved_cfg = (uint32_t *)gic_ctrl_suspend_resume.saved_cfg;
    gic_ctrl_suspend_resume.spi_lines = readl(gic.gic_dist_base + GICD_CTR) & 0x1F;

    /* gic disable */
    gic_ctrl_suspend_resume.saved_gic_cpu_ctrl_cfg = readl(gic.gic_cpu_base + GICC_CTLR);
    /* distributor disable */
    writel(0x0, gic.gic_dist_base + GICD_CTLR);
    ret = readl(gic.gic_cpu_base + GICC_CTLR);
    ret &= ~0x1U;
    writel(ret, gic.gic_cpu_base + GICC_CTLR);
    /* clear inter */
    for (i = 0; i <= gic_ctrl_suspend_resume.spi_lines; i++)
        writel(INVALID_VAL, gic.gic_dist_base + GICD_ICPENDRn + i * GICD_COUNT);

    /* save sec reg */
    for (i = 0; i <= gic_ctrl_suspend_resume.spi_lines; i++) {
        *p_saved_cfg = readl(gic.gic_dist_base + GICD_IGROUPn + i * GICD_COUNT);
        p_saved_cfg++;
    }
    /* save enable reg */
    for (i = 0; i <= gic_ctrl_suspend_resume.spi_lines; i++) {
        *p_saved_cfg = readl(gic.gic_dist_base + GICD_ISENABLERn + i * GICD_COUNT);
        p_saved_cfg++;
    }
    /* save priority reg */
    temp = PRIORITY_NUM * (gic_ctrl_suspend_resume.spi_lines + 1);
    for (cnt = 0; cnt < temp; cnt++) {
        *p_saved_cfg = readl(gic.gic_dist_base + GICD_IPRIORITYRn + cnt * GICD_COUNT);
        p_saved_cfg++;
    }
    gic_ctrl_suspend_resume.saved_cpu_primask_cfg = readl(gic.gic_cpu_base + GICC_PRIMASK);
    gic_ctrl_suspend_resume.saved_gic_cpu_bpr_cfg = readl(gic.gic_cpu_base + GICC_BP);
    gic_ctrl_suspend_resume.saved_gic_cpu_abpr_cfg = readl(gic.gic_cpu_base + GICC_ALIASED_BP);
    return;
}

void gic_cpu_resume(void)
{
    unsigned int cnt, temp;
    unsigned int *p_saved_cfg = (unsigned int *)gic_ctrl_suspend_resume.saved_cfg;

    /* resume sec reg */
    for (cnt = 0; cnt <= gic_ctrl_suspend_resume.spi_lines; cnt++) {
        writel(*p_saved_cfg, gic.gic_dist_base + GICD_IGROUPn + cnt * GICD_COUNT);
        p_saved_cfg++;
    }
    /* resume enable reg */
    for (cnt = 0; cnt <= gic_ctrl_suspend_resume.spi_lines; cnt++) {
        writel(*p_saved_cfg, gic.gic_dist_base + GICD_ISENABLERn + cnt * GICD_COUNT);
        p_saved_cfg++;
    }
    /* resume priority reg */
    temp = PRIORITY_NUM * (gic_ctrl_suspend_resume.spi_lines + 1);
    for (cnt = 0; cnt < temp; cnt++) {
        writel(*p_saved_cfg, gic.gic_dist_base + GICD_IPRIORITYRn + cnt * GICD_COUNT);
        p_saved_cfg++;
    }
    writel(gic_ctrl_suspend_resume.saved_cpu_primask_cfg, gic.gic_cpu_base + GICC_PRIMASK);
    writel(gic_ctrl_suspend_resume.saved_gic_cpu_bpr_cfg, gic.gic_cpu_base + GICC_BP);
    writel(gic_ctrl_suspend_resume.saved_gic_cpu_abpr_cfg, gic.gic_cpu_base + GICC_ALIASED_BP);
    writel(gic_ctrl_suspend_resume.saved_gic_cpu_ctrl_cfg, gic.gic_cpu_base + GICC_CTLR);
    /* distributor enable */
    writel(0x3, gic.gic_dist_base + GICD_CTLR);
}
#endif

static void gic_map_device(void *data)
{
    struct gic_config_t *config = data;
    kernel_frame_t frame = {0, 0, 0, true};

    gic.gic_dist_base = GIC2_DISTRIBUTOR_KADDR;
    frame.kaddr = gic.gic_dist_base;
    frame.paddr = config->v2.dist.start;
    frame.nr_pages = 1;
    map_kernel_device_frames(&frame, 1);

    gic.gic_cpu_base = GIC2_CONTROLLER_KADDR;
    frame.kaddr = gic.gic_cpu_base;
    frame.paddr = config->v2.contr.start;
    frame.nr_pages = 1;
    map_kernel_device_frames(&frame, 1);
}

struct gic_interface gic2_interface = {
    .__gic_set_irq_pend = gic_set_irq_pend,
    .__gic_set_irq_priority = gic_set_irq_priority,
    .__gic_set_irq_group = gic_set_irq_group,
    .__gic_set_irq_target = gic_set_irq_target,
    .__gic_set_exclusive_irq_target = gic_set_exclusive_irq_target,
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
    .ivt = hm_ivt_gic2,
    .__gic_trigger_set = gic_trigger_set,
};

device_descriptor_t gic2 = {
    .name = "gic_v2",
    .interface = &gic2_interface,
};
