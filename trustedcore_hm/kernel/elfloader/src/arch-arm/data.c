/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: elfloader data handle
 * Create: 2020-12
 */
#include <autoconf.h>
#include <config.h>
#include <log.h>
#include <data.h>
#include <elfloader.h>
#include <mmu.h>
#include <uart_register.h>
#include <arch/smp/smp.h>
#include <arch/machine/hardware.h>

#define DATA_SECTION_HOLD    1
ALIGN(BIT(PAGE_BITS)) VISIBLE char core_stacks[BIT(PAGE_BITS)];

int g_boot_num_app = 1;

HM_SPINLOCK(g_elfloader_lock);

/* .uart_type invalid initialization, because g_plat_cfg must not linked to bss section */
#ifdef NO_PLATCFG_EMBEDDED
struct platform_info g_plat_cfg = {
    .boot_args_size = 0x0,
    .uart_type = UART_DISABLE_FLAG,
};
#endif
/*
 * elf binary info that initialized by elfloader-main.c
 * and used by Hong Meng kernel init
 */
struct image_info g_kernel_info;

#ifdef CONFIG_ARCH_AARCH32
struct ns_kernel_info g_ns_info = { DATA_SECTION_HOLD,
                                    DATA_SECTION_HOLD,
                                    DATA_SECTION_HOLD,
                                    DATA_SECTION_HOLD,
                                    DATA_SECTION_HOLD };
#endif

paddr_t elfloader_kaddr_to_paddr(vaddr_t kaddr)
{
    return kaddr - (vaddr_t)(uintptr_t)_image_base_addr + BOOT_OFFSET + g_plat_cfg.phys_region_start;
}

vaddr_t elfloader_paddr_to_vaddr(paddr_t paddr)
{
    return paddr - g_plat_cfg.phys_region_start + (vaddr_t)(uintptr_t)_image_base_addr - BOOT_OFFSET;
}

void __stack_chk_fail(void)
{
    klog(DEBUG_ERROR, "stack chk failed!\n");
    halt();
}

void __ubsan_handle_out_of_bounds(__attribute__((unused)) void *data_ptr, __attribute__((unused)) unsigned long index)
{
    __builtin_trap();
}

/* The very basic halt with out stack dump */
void halt(void)
{
    while (1)
        wfi();
    UNREACHABLE();
}

void invalid_ivt_entry(void)
{
    ulong_t far = get_far();
    ulong_t elr = get_elr();
    ulong_t esr = get_esr();
    klog(DEBUG_ERROR, "ELF-LOADER: -------------------------\n");
    klog(DEBUG_ERROR, "ELF-LOADER: elr_el1:%lx far_el1:%lx esr_el1: %lx\n", elr, far, esr);
    klog(DEBUG_ERROR, "ELF-LOADER: -------------------------\n");
    fail("ELF-LOADER: Invalid exception received!\n");
}

void ivt_el1_sync(void)
{
    ulong_t far = get_far();
    ulong_t elr = get_elr();
    ulong_t esr = get_esr();
#ifdef CONFIG_ARCH_AARCH64
    ulong_t x0, x1, x2, x3, x4;
    __asm__ volatile("mov %0, x0\n"
                     "mov %1, x1\n"
                     "mov %2, x2\n"
                     "mov %3, x3\n"
                     "mov %4, x4\n"
                     : "=r"(x0), "=r"(x1), "=r"(x2), "=r"(x3), "=r"(x4)
                     :
                     :);
#endif
    klog(DEBUG_ERROR, "ELF-LOADER: -------------------------\n");
    klog(DEBUG_ERROR, "ELF-LOADER: elr_el1:%lx far_el1:%lx esr_el1: %lx\n", elr, far, esr);
#ifdef CONFIG_ARCH_AARCH64
    klog(DEBUG_ERROR, "ELF-LOADER: x0:0x%lx, x1:0x%lx, x2:0x%lx, x3:0x%lx, x4:0x%lx\n", x0, x1, x2, x3, x4);
#endif
    klog(DEBUG_ERROR, "ELF-LOADER: -------------------------\n");
    fail("ELF-LOADER: We should never receive sync in elfloader\n");
}

#ifdef CONFIG_GCOV
/* Dummy functions to make linker happy */
void llvm_gcda_summary_info()
{
}

void llvm_gcda_emit_arcs()
{
}

void llvm_gcda_emit_function()
{
}

void llvm_gcda_start_file()
{
}

void llvm_gcov_init()
{
}

void llvm_gcda_end_file()
{
}
#endif
