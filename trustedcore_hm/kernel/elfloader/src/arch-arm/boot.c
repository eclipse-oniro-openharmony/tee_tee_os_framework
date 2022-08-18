/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: elfloader smp boot function
 * Create: 2020-12
 */
#include <autoconf.h>
#include <log.h>
#include <assert.h>
#include <data.h>
#include <elfloader.h>
#include <arch/machine/registerset.h>
#include <mmu.h>
#include <random.h>
#include <snapshot.h>

#ifdef CONFIG_ARCH_AARCH64
#define PAR_PA_MASK 0x0000fffffffff000 /* bit 12-47 */
#else
#define PAR_PA_MASK 0x000000fffffff000 /* bit 12-39 */
#endif
static bool_t address_mapping_check(vaddr_t vaddr, paddr_t paddr)
{
    vaddr_t va = vaddr;
    paddr_t pa;

#ifdef CONFIG_ARCH_AARCH64
    __asm__ volatile("AT S1E1W, %0" ::"r"(va));
    __asm__ volatile("isb");
    MRS("PAR_EL1", pa);
#else
    MCR("p15, 0, %0, c7, c8, 1", va);
    __asm__ volatile("mrrc p15, 0, %Q0, %R0, c7" : "=r" (pa));
#endif

    if ((pa & PAR_PA_MASK) == (paddr & PAR_PA_MASK)) {
        return true;
    } else {
        klog(DEBUG_ERROR, "checking address mapping, vaddr = %llx,"
            "paddr = %llx, expect paddr = %llx\n",
            vaddr, paddr, pa);
        fail("address mapping check fail\n");
    }
}

void boot_kernel(uint64_t uart_used, uint64_t elfloader_map_size)
{
    if ((paddr_t)(uintptr_t)_image_base_addr < BOOT_OFFSET)
        fail("image_base_addr less than boot offset, maybe config errors\n");
    struct elfloader_to_kernel_args boot_args;
#ifdef CONFIG_AARCH32_MONITOR
    g_plat_cfg.ns_kernel_info_paddr = (paddr_t)(uintptr_t)&g_ns_info;
#endif
    struct image_info *user_info = get_user_img_info();
    if (user_info == NULL)
        fail("invalid user image\n");
    klog(DEBUG_INFO, "UART_PPTR = 0x%llx\n", g_plat_cfg.uart_addr);
    /* We need the following so that we can still hold the UARD memory mapped in our vspace */
    ASSERT(g_kernel_info.virt_region_start > g_plat_cfg.uart_addr);
    /* Before and after enable mmu, kernel_ivo.virt_region_start should pointed to the same physical address */
    ASSERT(address_mapping_check(g_kernel_info.virt_region_start, g_kernel_info.phys_region_start));

    boot_args.user_img_info      = user_info;
    boot_args.num_apps           = g_boot_num_app;
    boot_args.kernel_img_info    = &g_kernel_info;
    boot_args.plat_cfg_info      = &g_plat_cfg;
    boot_args.uart_used          = uart_used;
    boot_args.uart_paddr         = g_plat_cfg.uart_addr;
    boot_args.elfloader_map_size = elfloader_map_size;

    boot_args.rand_num = rand_get(g_plat_cfg.random_seed);

    klog(DEBUG_INFO, "ready jump to kernel from elfloader\n");
    ((init_kernel_t)(uintptr_t)g_kernel_info.virt_entry)(&boot_args);
    fail("elf-loader kernel_init should not return back to this spot! ");
}
