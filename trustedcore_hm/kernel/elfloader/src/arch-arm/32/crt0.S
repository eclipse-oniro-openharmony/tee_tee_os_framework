/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: elfloader init
 * create user && kernel vspace pagetable, map uart device
 * Create: 2021-03
 */
#include <machine/assembler.h>
#include <mode/object/structures.h>
#include <mode/api/constants.h>
#include <arch/machine/registerset.h>
#include <plat/machine/devices.h>
#include "mmu.h"

    .extern core_stacks
    .extern main
    .extern elfloader_ivt
    .extern g_ns_info
    .extern g_plat_cfg

    .section ".inittext", "ax"

.macro set_sctlr_el1
    mrs r0, sctlr_el1
    orr r0, r0, #SCTLR_I
    orr r0, r0, #SCTLR_SA
    bic r0, r0, #SCTLR_A
    msr sctlr_el1, r0
.endm

.macro get_pgd_index
    lsr r0, r0, #PGD_INDEX_OFFSET
    ldr r1, =(1 << UPGD_INDEX_BITS)
    sub r1, r1, #1
    and r0, r0, r1
.endm

.macro get_pd_index
    lsr r0, r0, #PD_INDEX_OFFSET
    ldr r1, =(1 << PD_INDEX_BITS)
    sub r1, r1, #1
    and r0, r0, r1
.endm

.macro get_pt_index
    lsr r0, r0, #PT_INDEX_OFFSET
    ldr r1, =(1 << PT_INDEX_BITS)
    sub r1, r1, #1
    and r0, r0, r1
.endm

.macro algin_up
    sub r1, r1, #1
    add r0, r0, r1
    mvn r1, r1
    and r0, r0, r1
.endm

/*
 * input  : virtual  address stored in r5
 * output : physical address stored in r5
 */
.macro virt_to_phys
    adr r0, _start
    ldr r12, =_image_base_addr
    sub r5, r5, r12
    add r5, r5, r0
.endm

.section ".text.start"

/*
 * r13 : tee physical region size
 * r7  : elfloader map region
 */
BEGIN_FUNC(_start)
    ldr r5, =g_ns_info
    mov r6, r0
    virt_to_phys
    mov r0, r6
    stmia r5, {r0-r3}
    bl enable_cpacr
    bl enable_fpu

    bl copy_plat_cfg

    ldr r0, =ELFLOADER_MAP_SIZE
    cmp r13, r0
    bhi set_mmu_size
    mov r0, r13
set_mmu_size:
    mov r7, r0
    bl core_init_mmu_map
    bl core_init_mmu_regs
    bl cpu_mmu_enable

start_after_mmu_enable:
    bl set_ivt_vector

    bl clear_bss
    /*
     * start elfloader main function
     * r1 = teeos mem size
     * r2 = teeos mem start
     */
    mov r2, r8
    mov r1, r13
    bl enable_cntpct_el0
    bl setup_sp
    b main
END_FUNC(_start)

BEGIN_FUNC(set_ivt_vector)
    ldr r0, =elfloader_ivt
    mcr p15, 0, r0, c12, c0, 0
    mov pc, lr
END_FUNC(set_ivt_vector)

BEGIN_FUNC(enable_cpacr)
    mrc p15, 0, r0, c1, c0, 2
    orr r0, r0, #(3 << 20)
    orr r0, r0, #(3 << 22)
    bic r0, r0, #(3 << 30)
    mcr p15, 0, r0, c1, c0, 2
    mov pc, lr
END_FUNC(enable_cpacr)

/*
 * r1 = g_plat_cfg buffer size
 * r0 = g_plat_cfg memory start phys addr from bootloader
 * r4 = g_plat_cfg memory end   phys addr from bootloader
 */
BEGIN_FUNC(copy_plat_cfg)
#ifdef BOOT_ARGS_TRANSFER
    adr r5, _start
    lsr r5,  r5, #PD_INDEX_OFFSET
    lsl r5,  r5, #PD_INDEX_OFFSET
    ldr r1, [r5]
    add r5, #8
    ldr r13, [r5]
    sub r5, r5, #8
    mov r0, r5
    ldr r5, =g_plat_cfg
    mov r6, r0
    virt_to_phys
    mov r0, r6
    mov r2, r5
    add r4, r0, r1
copy_cfg:
    ldr r3, [r0]
    str r3, [r2]
    add r0, r0, #8
    add r2, r2, #8
    cmp r0, r4
    blo copy_cfg
    mov pc, lr
#else
    ldr r5, =g_plat_cfg
    virt_to_phys
    mov r0, r5
    add r0, r0, #8
    ldr r13, [r0]
    mov pc, lr
#endif
END_FUNC(copy_plat_cfg)

BEGIN_FUNC(enable_fpu)
    mov    r3, #0x40000000
    vmsr   FPEXC, r3
    mov pc, lr
END_FUNC(enable_fpu)

BEGIN_FUNC(clear_bss)
    ldr r0, =__data_end
    ldr r1, =__bss_end
memset_bss:
    mov r2, #0
    str r2, [r0]
    add r0, r0, #4
    cmp r0, r1
    blo memset_bss
    mov pc, lr
END_FUNC(clear_bss)

BEGIN_FUNC(enable_cntpct_el0)
    mrc p15, 0, r5, c14, c1, 0
    orr r5, r5, #1
    mcr p15, 0, r5, c14, c1, 0
END_FUNC(enable_cntpct_el0)

BEGIN_FUNC(setup_sp)
    ldr r5, =core_stacks
    add r5, r5, #0xff0
    mov sp, r5
    mov pc, lr
END_FUNC(setup_sp)

/* r11: kernel_pmd */
BEGIN_FUNC(map_uart_in_kernel_space)
    /* set level 0 pagetable: entry0 */
    ldr r5, =g_plat_cfg
    virt_to_phys
    mov r0, r5
    /* get UART PADDR */
    add r0, r0, #24
    ldr r3, [r0]
    lsr r3, r3, #PD_INDEX_OFFSET
    lsl r3, r3, #PD_INDEX_OFFSET
    ldr r4, =(MMU_BLOCK_FLAG | PTE_AF_ATTR | PTE_ATTRIDX(MEM_DEVICE_NGNRNE_TYPE))
    orr r3, r3, r4
    ldr r0, =UART6_KADDR
    get_pd_index
    mov r5, r0
    lsl r5, r5, #PMD_ORDER
    add r5, r5, r11
    str r3, [r5]
    mov pc, lr
END_FUNC(map_uart_in_kernel_space)

/*
 * user pagetables layout:
 * start:0
 *         --------------------------------
 *        |  4k  |     4k     |    4k     |
 *         --------------------------------
 *  user_pgd  user_pud    user_pmd
 *        r6     r9           r10
 * r5:  phys addr of _start func
 * r8:  base_phy_addr
 * r9:  level 1 pagetables phys addr user_pud
 * r10: level 2 pagetables phys addr user_pmd
 * r13: phys region size
 * we use only user_pud(r9) && user_pmd(r10)
 */
BEGIN_FUNC(core_init_mmu_map)
    /* r5 = phys addr of _start */
    adr r5, _start

    /* r8/r6 = start/end of phys addr of pagetables */
    lsr r5,  r5, #PD_INDEX_OFFSET
    lsl r5,  r5, #PD_INDEX_OFFSET
    mov r8,  r5  /* x8 = base_phy_addr */
    add r6,  r8, #BOOT_OFFSET
    add r9,  r8, #USER_LEVEL1_OFFSET
    add r10, r8, #USER_LEVEL2_OFFSET

    mov r4, r8
clear_pagetable:
    mov r2, #0
    str r2, [r4]
    add r4, r4, #4
    cmp r4, r6
    blo clear_pagetable

    /* set level 0 pagetable */
    mov r3, r10
    ldr r4, =MMU_VALID_TABLE_FLAG /* set table flags BIT(1) | BIT(0) */
    orr r3, r3, r4
    mov r0, r8
    get_pgd_index
    lsl r0, r0, #PMD_ORDER
    add r0, r0, r9
    str r3, [r0]

    /* set level 1 pagetable */
    mov r0, r7
    ldr r1, =(1 << hm_LargePageBits)
    algin_up
    lsr r1, r1, #hm_LargePageBits
    mov r1, r0
    mov r0, r8
    get_pd_index
    add r1, r1, r0

    /* r0 pmd_start, r1 pmd_end */
    mov r11, r0
set_user_pmd:
    sub r3, r0, r11
    lsl r3, r3, #hm_LargePageBits
    add r3, r3, r8
    ldr r4, =(MMU_BLOCK_FLAG | PTE_AF_ATTR | PTE_ATTRIDX(MEM_MT_NORMAL))
    orr r3, r3, r4
    mov r5, r0
    lsl r5, r5, #PMD_ORDER
    add r5, r5, r10
    str r3, [r5]
    add r0, r0, #1
    cmp r0, r1
    blo set_user_pmd

/*
 * kernel pagetables layout
 * start:0
 *        ---------------------------------------------------------------
 *       |    12KB      |       4k      |       4k      |        4k      |
 *        ---------------------------------------------------------------
 *                  kernel_pgd         kernel_pud      kernel_pmd
 *                      r9             r10              r11
 */
    add r10, r8, #KERNEL_LEVEL1_OFFSET
    add r11, r8, #KERNEL_LEVEL2_OFFSET
    ldr r12, =_image_base_addr  /* code virt addr start */

    /* set level 0 pagetable: entry0 */
    mov r0, r7
    ldr r1, =(1 << hm_LargePageBits)
    algin_up
    lsr r1, r1, #hm_LargePageBits
    mov r1, r0
    mov r0, r12
    get_pd_index
    add r1, r1, r0
    /* r0 pmd_start, r1 pmd_end */

    mov r3, r0
    mov r6, r0
set_kernel_pmd:
    sub r3, r0, r6
    lsl r3, r3, #hm_LargePageBits
    add r3, r3, r8
    ldr r4, =(MMU_BLOCK_FLAG | PTE_AF_ATTR | MEM_SHARE_ATTR | PTE_ATTRIDX(MEM_MT_NORMAL))
    orr r3, r3, r4
    mov r5, r0
    lsl r5, r5, #PMD_ORDER
    add r5, r5, r11
    str r3, [r5]
    add r0, r0, #1
    cmp r0, r1
    blo set_kernel_pmd

    mov r6, lr
    bl map_uart_in_kernel_space

    /* set ttbr0 && ttbr1 to return value */
    mov r0, r9
    mov r3, r11
    mov pc, r6
END_FUNC(core_init_mmu_map)

/* void core_init_mmu_regs(ttbr0) */
BEGIN_FUNC(core_init_mmu_regs)
    /* setup mair0 */
    ldr r1, =(MAIR_DEVICE_NGNRNE | MAIR_DEVICE_NGNRE | \
              MAIR_DEVICE_GRE | MAIR_NORMAL_NC)
    mcr p15, 0, r1, c10, c2, 0
    /* setup mair1 */
    ldr r1, =0xff
    mcr p15, 0, r1, c10, c2, 1
    isb
    dsb

/*
 * TOSZ = 0, TTBR0 covers 3GB starting at 0x0
 * T1SZ = 1, TTBR1 convers 1GB starting at 0xC0000000
 */
    ldr r1, =(TTBCR_EAE | (TTBCR_XRGNX_WBWA << TTBCR_IRGN0_SHIFT) | (TTBCR_XRGNX_WBWA << TTBCR_ORGN0_SHIFT) | \
              (TTBCR_SHX_ISH << TTBCR_SH0_SHIFT) | (TTBCR_XRGNX_WBWA << TTBCR_IRGN1_SHIFT) | (TTBCR_XRGNX_WBWA << TTBCR_ORGN1_SHIFT) | \
              (TTBCR_SHX_ISH << TTBCR_SH1_SHIFT) | (0x0 << TTBCR_T0SZ_SHIFT) | (0x2 << TTBCR_T1SZ_SHIFT))

    mcr p15, 0, r1, c2, c0, 2
    isb
    dsb

    mov r1, #0
    mcrr p15, 0, r0, r1, c2
    mcrr p15, 1, r3, r1, c2
    isb
    dsb
    mov pc, lr
END_FUNC(core_init_mmu_regs)

/* void cpu_mmu_enable(void) */
BEGIN_FUNC(cpu_mmu_enable)
    /* Invalidate TLB */
    mov r0, #0
    mcr p15, 0, r0, c8, c7, 0
    mcr p15, 0, r0, c8, c3, 0
    mcr p15, 0, r0, c7, c5, 6

    /* Enable the MMU */
    mrc p15, 0, r0, c1, c0, 0
    orr r0, r0, #SCTLR_M
    orr r0, r0, #SCTLR_I
    orr r0, r0, #SCTLR_C
    mcr p15, 0, r0, c1, c0, 0
    isb
    dsb

    ldr r0, =start_after_mmu_enable
    mov pc, r0
END_FUNC(cpu_mmu_enable)
