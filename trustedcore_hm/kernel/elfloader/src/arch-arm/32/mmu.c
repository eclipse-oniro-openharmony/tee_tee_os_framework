/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: elfloader mmu function
 * Create: 2020-12
 */
#include <log.h>
#include <types.h>
#include <elfloader.h>
#include <plat/config.h>
#include <data.h>
#include <arch/machine/registerset.h>
#include <mode/object/structures.h>
#include "io.h"
#include <mmu.h>

#define CONFIG_KERNEL_BASE_ADDR 0xc0000000

/* map devices VA=PA */
void map_devices(uint64_t dst_addr)
{
    vaddr_t *user_pud = (vaddr_t *)(uintptr_t)((vaddr_t)(uintptr_t)_image_base_addr - BOOT_OFFSET + USER_LEVEL1_OFFSET);
    vaddr_t *user_pmd = (vaddr_t *)(uintptr_t)((vaddr_t)(uintptr_t)_image_base_addr - BOOT_OFFSET + USER_LEVEL2_OFFSET);
    paddr_t user_pmd_phy = g_plat_cfg.phys_region_start + USER_LEVEL2_OFFSET;

    user_pud[GET_PGD_INDEX(dst_addr)] = ((uintptr_t)user_pmd_phy) | MMU_VALID_TABLE_FLAG; /* its a page table */

    uint32_t pmd  = (uint32_t)(GET_PD_INDEX(dst_addr));
    user_pmd[pmd] = ((dst_addr >> hm_LargePageBits) << hm_LargePageBits)
                    | MMU_BLOCK_FLAG | PTE_AF_ATTR | PTE_ATTRIDX(MEM_DEVICE_NGNRNE_TYPE);
}
/*
 * Create a "boot" page table, which contains a 1:1 mapping below
 * the kernel's first vaddr, and a virtual-to-physical mapping above the
 * kernel's first vaddr.
 */
#ifdef CONFIG_KERNEL_ASLR
ulong_t get_aslr_kernel_offset(void);
#endif
void init_kernel_vspace(void)
{
    ulong_t i;
    uint64_t size = g_plat_cfg.phys_region_size;
    vaddr_t *kernel_pmd = (vaddr_t *)(uintptr_t)((vaddr_t)(uintptr_t)_image_base_addr - \
                           BOOT_OFFSET + KERNEL_LEVEL2_OFFSET);

#ifdef CONFIG_KERNEL_ASLR
    ulong_t first_pt_index = (get_aslr_kernel_offset() - \
                              KERNEL_LOAD_OFFSET - CONFIG_KERNEL_BASE_ADDR) >> hm_LargePageBits;
#else
    ulong_t first_pt_index = 0;
#endif
    klog(DEBUG_WARNING, "first_pt_index=0x%lx\n", first_pt_index);
    paddr_t first_paddr = g_plat_cfg.phys_region_start;
    size = size > ELFLOADER_MAP_SIZE ? ELFLOADER_MAP_SIZE : size;
    /* phys_region_size should align up */
    uint32_t pmd_end = ALIGN_UP(size, BIT(hm_LargePageBits)) >> hm_LargePageBits;

    /* map kernel space to 0xc0000000 */
    for (i = 0; i < pmd_end; i++)
        kernel_pmd[i + first_pt_index] = (((i) << hm_LargePageBits) +
                         ((first_paddr >> hm_LargePageBits) << hm_LargePageBits)) |
                         PTE_AF_ATTR | /* access flag */
#if CONFIG_MAX_NUM_NODES > 1
                         MEM_SHARE_ATTR | /* make sure the shareability is the same as the kernel's */
#endif
                         PTE_ATTRIDX(MEM_MT_NORMAL) | /* normal memory */
                         MMU_BLOCK_FLAG; /* 2M block */
}

#ifdef CONFIG_KERNEL_ASLR
/*
 * 2MB granule at 32-bit version
 * don't need extra designated space to store pagetable
 */
uint64_t get_kaslr_pg_size(uint64_t map_size)
{
    (void)map_size;
    return 0;
}
#endif
