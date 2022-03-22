/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: elfloader init
 * create user && kernel vspace pagetable, map uart device
 * Create: 2021-03
 */
#include <machine/assembler.h>
#include <mode/object/structures.h>
#include <mode/api/constants.h>
#include <plat/machine/devices.h>
#include <arch/machine/registerset.h>
#include <mode/sysreg.h>
#include <mmu.h>

    .extern main_stacks
    .extern main
    .extern elfloader_ivt
    .extern g_plat_cfg
    .section ".inittext", "ax"

.macro set_sctlr_el1
    mrs x0, sctlr_el1
    orr x0, x0, #SCTLR_SA
    bic x0, x0, #SCTLR_A
    msr sctlr_el1, x0
.endm

.macro get_pgd_index
    lsr x0, x0, #PGD_INDEX_OFFSET
    ldr x1, =(1 << PGD_INDEX_BITS)
    sub x1, x1, #1
    and x0, x0, x1
.endm

.macro get_pud_index
    lsr x0, x0, #PUD_INDEX_OFFSET
    ldr x1, =(1 << PUD_INDEX_BITS)
    sub x1, x1, #1
    and x0, x0, x1
.endm

.macro get_pd_index
    lsr x0, x0, #PD_INDEX_OFFSET
    ldr x1, =(1 << PD_INDEX_BITS)
    sub x1, x1, #1
    and x0, x0, x1
.endm

.macro get_pt_index
    lsr x0, x0, #PT_INDEX_OFFSET
    ldr x1, =(1 << PT_INDEX_BITS)
    sub x1, x1, #1
    and x0, x0, x1
.endm

.macro algin_up
    sub x1, x1, #1
    add x0, x0, x1
    mvn x1, x1
    and x0, x0, x1
.endm

.section ".text.start"

/*
 * x13 : tee physical region size
 * x16 : elfloader mapping regions
 */
BEGIN_FUNC(_start)
    /*
     * x5  = phys  addr start of elfloader code
     * x8  = phys  addr start of teeos reserved memory
     * x6  = start addr of pagetables
     * x7  = end   addr of pagetables
     * x13 = tee memory size
     * x14 = uart addr
     */
    adr x5, _start
    lsr x6, x5, #PD_INDEX_OFFSET
    lsl x6, x6, #PD_INDEX_OFFSET
    mov x8, x6  /* x8 = base_phy_addr */
    add x7, x6, #BOOT_OFFSET

    bl copy_plat_cfg

    isb
    set_sctlr_el1
    isb

    /* teeos mem size stored in x13 */
    ldr x0, =ELFLOADER_MAP_SIZE
    cmp x13, x0
    bhi set_mmu_size
    mov x0, x13
set_mmu_size:
    mov x16, x0
    bl core_init_mmu_map
    bl core_init_mmu_regs
    bl cpu_mmu_enable

start_after_mmu_enable:
    bl cpu_mmu_enable_icache
    bl cpu_mmu_enable_dcache
    bl set_ivt_vector
    bl clear_bss
    bl enable_cntpct_el0
    bl setup_sp

    /*
     * start elfloader main function
     * x1 = teeos mem size
     * x2 = teeos mem start
     */
    mov x2, x8
    mov x1, x13
    b main
    ret
END_FUNC(_start)

BEGIN_FUNC(set_ivt_vector)
    /* set VABR = elfloader_ivt(VA) */
    adr x0, elfloader_ivt
    msr vbar_el1, x0
    ret
END_FUNC(set_ivt_vector)

/*
 * x1  = g_plat_cfg buffer size
 * x0  = g_plat_cfg memory start phys addr from bootloader
 * x4  = g_plat_cfg memory end   phys addr from bootloader
 * x2  = g_plat_cfg memory phys addr in   teeos
 * copy to x2 from x0, size=x1
 * store teeos mem size in x13
 */
BEGIN_FUNC(copy_plat_cfg)
    mov x20, x30
#ifdef BOOT_ARGS_TRANSFER
    mov x0, x8
    ldr x1, [x0]
    bl copy_paras
    mov x2, x13
    mov x0, x8
    adr x2, g_plat_cfg
    add x4, x0 ,x1
copy_cfg:
    ldr x3, [x0]
    str x3, [x2]
    add x0, x0, #8
    add x2, x2, #8
    cmp x0, x4
    blo copy_cfg
    mov x30, x20
    ret
#else
    adr x0, g_plat_cfg
    bl copy_paras
    mov x30, x20
    ret
#endif
END_FUNC(copy_plat_cfg)

/*
 * copy teeos mem size to x13
 * copy uart addr to x14
 * x0: addr of plat_cfg
 */
BEGIN_FUNC(copy_paras)
    add x0, x0, #8
    ldr x13, [x0]
    add x0, x0, #16
    ldr x14, [x0]
    ret
END_FUNC(copy_paras)

BEGIN_FUNC(clear_bss)
    ldr x0, =__data_end
    ldr x1, =__bss_end
memset_bss:
    str xzr, [x0]
    add x0, x0, #8
    cmp x0, x1
    blo memset_bss
    ret
END_FUNC(clear_bss)

BEGIN_FUNC(enable_cntpct_el0)
    mrs x0, cntkctl_el1
    orr x0, x0, 0x1
    msr cntkctl_el1, x0
    ret
END_FUNC(enable_cntpct_el0)

BEGIN_FUNC(setup_sp)
    msr spsel, #1
    ldr x0, =core_stacks
    add x0, x0, #0xff0
    mov sp, x0
    ret
END_FUNC(setup_sp)

/*
 * x9:  level0 in kernel vspace
 * x10: level1 in kernel vspace
 * x11: level2 in kernel vspace
 */
BEGIN_FUNC(map_uart_in_kernel_space)
    /* set level 0 pagetable */
    add x11, x6, #DEVICE_LEVEL2_OFFSET
    mov x3, x10
    ldr x4, =MMU_VALID_TABLE_FLAG /* set table flags BIT(1) | BIT(0) */
    orr x3, x3, x4
    ldr x0, =UART6_KADDR
    get_pgd_index
    lsl x0, x0, #PMD_ORDER
    add x0, x0, x9
    str x3, [x0]

    /* set level 1 pagetable: entry0 */
    mov x3, x11
    ldr x4, =MMU_VALID_TABLE_FLAG /* set table flags BIT(1) | BIT(0) */
    orr x3, x3, x4
    ldr x0, =UART6_KADDR
    get_pud_index
    lsl x0, x0, #PMD_ORDER
    add x0, x0, x10
    str x3, [x0]

    /* set level 2 pagetable */
    mov x3, x14
    lsr x3, x3, #PD_INDEX_OFFSET
    lsl x3, x3, #PD_INDEX_OFFSET
    ldr x4, =(MMU_BLOCK_FLAG | PTE_AF_ATTR | PTE_ATTRIDX(MEM_DEVICE_NGNRNE_TYPE) | MEM_SHARE_ATTR)
    orr x3, x3, x4
    ldr x0, =UART6_KADDR
    get_pd_index
    mov x5, x0
    lsl x5, x5, #PMD_ORDER
    add x5, x5, x11
    str x3, [x5]
    ret
END_FUNC(map_uart_in_kernel_space)

/*
 * start:0
 *         --------------------------------
 *        |  4k  |     4k     |    4k     |
 *         --------------------------------
 *         user_pgd  user_pud    user_pmd
 *        x6     x9           x10
 * x5:  phys addr of _start func
 * x6:  phys addr of pagetables start user_pgd
 * x7:  phys addr of pagetables end
 * x8:  base_phy_addr
 * x9:  level 1 pagetables phys addr user_pud
 * x10: level 2 pagetables phys addr user_pmd
 * x13: phys region size
 * x14: regs to be mapped
 */
BEGIN_FUNC(core_init_mmu_map)
    /* store elr */
    mov x20, x30
    add x9,  x6, #USER_LEVEL1_OFFSET
    add x10, x6, #USER_LEVEL2_OFFSET

    mov x4, x6
clear_pagetable:
    str xzr, [x4], #(1 << PMD_ORDER)
    cmp x4, x7
    b.lt clear_pagetable

    /* set level 0 pagetable */
    mov x3, x9
    ldr x4, =MMU_VALID_TABLE_FLAG
    orr x3, x3, x4
    mov x0, x8
    get_pgd_index
    lsl x0, x0, #PMD_ORDER
    add x0, x0, x6
    str x3, [x0]

    /* set level 1 pagetable */
    mov x3, x10
    ldr x4, =MMU_VALID_TABLE_FLAG
    orr x3, x3, x4
    mov x0, x8
    get_pud_index
    lsl x0, x0, #PMD_ORDER
    add x0, x0, x9
    str x3, [x0]

    /* set level 2 pagetable, one block(2MB) is enough */
    mov x0, x8
    get_pd_index
    mov  x3, x8
    ldr  x4, =(MMU_BLOCK_FLAG | PTE_AF_ATTR | PTE_ATTRIDX(MEM_MT_NORMAL) | MEM_SHARE_ATTR)
    orr  x3, x3, x4
    mov  x5, x0
    lsl  x5, x5, #PMD_ORDER
    add  x5, x5, x10
    str  x3, [x5]

/*
 * kernel pagetables layout
 * start:0
 *        ---------------------------------------------------------------
 *       |    12KB      |       4k      |       4k      |        4k      |
 *        ---------------------------------------------------------------
 *                  kernel_pgd         kernel_pud      kernel_pmd
 *                      x9             x10              x11
 */
    add x9,  x6, #KERNEL_LEVEL0_OFFSET
    add x10, x6, #KERNEL_LEVEL1_OFFSET
    add x11, x6, #KERNEL_LEVEL2_OFFSET

    ldr x12, =_image_base_addr  /* code virt addr start */
    /* set level 0 pagetable */
    mov x3, x10
    ldr x4, =MMU_VALID_TABLE_FLAG
    orr x3, x3, x4
    mov x0, x12
    get_pgd_index
    lsl x0, x0, #PMD_ORDER
    add x0, x0, x9
    str x3, [x0]

    /* set level 1 pagetable */
    mov x3, x11
    ldr x4, =MMU_VALID_TABLE_FLAG
    orr x3, x3, x4
    mov x0, x12
    get_pud_index
    lsl x0, x0, #PMD_ORDER
    add x0, x0, x10
    str x3, [x0]

    mov x0, x16
    ldr x1, =(1 << hm_LargePageBits)
    algin_up
    lsr x3, x0, #hm_LargePageBits
    mov x0, x12
    get_pd_index
    add x1, x3, x0
    /* x0 pmd_index_start, x1_index pmd_end */

    mov x15, x0
3:
    sub x3, x0, x15
    lsl x3, x3, #hm_LargePageBits
    add x3, x3, x8
    ldr x4, =(MMU_BLOCK_FLAG | PTE_AF_ATTR | PTE_ATTRIDX(MEM_MT_NORMAL) | MEM_SHARE_ATTR)
    orr x3, x3, x4
    mov x5, x0
    lsl x5, x5, #PMD_ORDER
    add x5, x5, x11
    str x3, [x5]
    add x0, x0, #1
    cmp x0, x1
    b.ls 3b

    bl map_uart_in_kernel_space

    /* set level 0 pagetable to return value */
    mov x0, x6
    mov x3, x9

    /* restore elr */
    mov x30, x20
    ret
END_FUNC(core_init_mmu_map)

/* void core_init_mmu_regs(ttbr0) */
BEGIN_FUNC(core_init_mmu_regs)
    ldr x1, =(MAIR_DEVICE_NGNRNE | MAIR_DEVICE_NGNRE | \
              MAIR_DEVICE_GRE | MAIR_NORMAL_NC | MAIR_NORMAL)
    msr mair_el1, x1

    ldr x1, =(TCR_T0SZ(48UL) | TCR_T1SZ(48UL) | TCR_IRGN0_WBWA | TCR_IRGN1_WBWA | TCR_ORGN0_WBWA | TCR_ORGN1_WBWA | \
              TCR_SH0_INNER  | TCR_SH1_INNER  | TCR_TG0(0UL)   | TCR_TG1_4K     | TCR_AS(1UL))
/*
 * get Intermediate Physical Size
 * 0b00  32bits 4GB
 * 0b001 36bits 64GB
 * 0b010 40bits 1TB
 * 0b011 42bits 4TB
 * 0b100 44bits 16TB
 * 0b101 48bits 256TB
 * 0b110 52bits 4PB
 */
    mrs x4, ID_AA64MMFR0_EL1
    and x4, x4, 0xf
    lsl x4, x4, #TCR_IPS_OFFSET
    orr x1, x1, x4
    msr tcr_el1, x1

    msr ttbr0_el1, x0
    msr ttbr1_el1, x3
    ret
END_FUNC(core_init_mmu_regs)

/* void cpu_mmu_enable(void) */
BEGIN_FUNC(cpu_mmu_enable)
    /* Invalidate TLB */
    tlbi vmalle1is

    /*
     * Make sure translation table writes have drained in the memory and
     * the TLB invalidation is complete.
     */
    dsb sy
    isb

    /* Write register sctlr_el1, enable the MMU */
    mrs x0, sctlr_el1
    orr x0, x0, #SCTLR_M
    msr sctlr_el1, x0
    isb

    ldr x0, =start_after_mmu_enable
    ret x0
END_FUNC(cpu_mmu_enable)

BEGIN_FUNC(cpu_mmu_enable_icache)
    /* Invalidate instruction cache and branch predictor */
    ic iallu
    isb
    mrs x0, sctlr_el1
    orr x0, x0, #SCTLR_I
    msr sctlr_el1, x0
    isb
    ret
END_FUNC(cpu_mmu_enable_icache)

BEGIN_FUNC(cpu_mmu_enable_dcache)
    mrs x0, sctlr_el1
    orr x0, x0, #SCTLR_C
    msr sctlr_el1, x0
    isb
    ret
END_FUNC(cpu_mmu_enable_dcache)
