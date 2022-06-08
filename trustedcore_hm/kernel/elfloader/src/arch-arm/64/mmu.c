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
#include <mode/sysreg.h>
#include <mmu.h>
#include <snapshot.h>

#define KERNEL_PMD_CNT 2

/* Paging structures for kernel mapping */
#ifndef CONFIG_KERNEL_ASLR
static uint64_t g_kernel_pmd[BIT(hm_PageDirIndexBits)] ALIGN(BIT(hm_PageDirBits));
#else
static pde_t g_kernel_pmd[KERNEL_PMD_CNT][BIT(hm_PageDirIndexBits)] ALIGN(BIT(hm_PageDirBits));
#endif

/* map devices VA=PA */
void map_devices(uint64_t dst_addr)
{
    vaddr_t *user_pgd = (vaddr_t *)(uintptr_t)((vaddr_t)(uintptr_t)_image_base_addr - BOOT_OFFSET + USER_LEVEL0_OFFSET);
    vaddr_t *user_pud = (vaddr_t *)(uintptr_t)((vaddr_t)(uintptr_t)_image_base_addr - BOOT_OFFSET + USER_LEVEL1_OFFSET);
    vaddr_t *user_pmd = (vaddr_t *)(uintptr_t)((vaddr_t)(uintptr_t)_image_base_addr - BOOT_OFFSET + USER_LEVEL2_OFFSET);
    paddr_t user_pud_phy = g_plat_cfg.phys_region_start + USER_LEVEL1_OFFSET;
    paddr_t user_pmd_phy = g_plat_cfg.phys_region_start + USER_LEVEL2_OFFSET;

    user_pgd[GET_PGD_INDEX(dst_addr)] = ((uintptr_t)user_pud_phy) | MMU_VALID_TABLE_FLAG; /* its a page table */
    user_pud[GET_PUD_INDEX(dst_addr)] = ((uintptr_t)user_pmd_phy) | MMU_VALID_TABLE_FLAG; /* its a page table */

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

#include <../kernel/vspace.h>
#include <string.h>

#define PD_OFFSET(x) ((x) >> (PUD_INDEX_OFFSET))
#define PT_OFFSET(x) ((x) >> (PD_INDEX_OFFSET))

#define PD_BASE PD_OFFSET(first_vaddr)
#define PT_BASE PT_OFFSET(first_vaddr)

#define PD_ARRAY_INDEX(x) (PD_OFFSET(x) - PD_BASE)
#define PT_ARRAY_INDEX(x) (PT_OFFSET(x) - PT_BASE)

#define PT_TOP PT_OFFSET(end_vaddr - 1)
#define PT_ARRAY_SIZE (PT_TOP - PT_BASE + 1)

static void pgtable_set(vaddr_t first_vaddr,
                        paddr_t first_paddr, pde_t *pmd_ptr, pte_array_t *kernel_pt)
{
    vaddr_t vaddr;
    paddr_t paddr;

    pde_pde_small_ptr_new(&pmd_ptr[GET_PD_INDEX(first_vaddr)],
                          elfloader_kaddr_to_paddr((paddr_t)(uintptr_t)(kernel_pt)));
    klog(DEBUG_LOG, "set vaddr 0x%lx pmd entry to 0x%llx at virtual %p\n",
         (unsigned long)first_vaddr,
         (unsigned long long)elfloader_kaddr_to_paddr((paddr_t)(uintptr_t)(kernel_pt)),
         &pmd_ptr[GET_PD_INDEX(first_vaddr)]);

    paddr = first_paddr;
    for (vaddr = first_vaddr; vaddr < first_vaddr + BIT(PD_INDEX_OFFSET); vaddr += BIT(hm_PageBits)) {
        uint64_t AP = VMEM_KERNEL;
        uint64_t PXN = 0;
        pte_ptr_new_ex (
            &kernel_pt[PT_ARRAY_INDEX(vaddr)][GET_PT_INDEX(vaddr)],
            1,                        /* unprivileged execute never */
            PXN,
            paddr,
            0,                        /* global */
            1,                        /* access flag */
#if CONFIG_MAX_NUM_NODES > 1
            ATTR_SHARED,
#else
            ATTR_NONSHARED,
#endif
            AP,                       /* VMEM_KERNEL */
            0,                        /* Non-secure bit */
            NORMAL,
            MMU_TABLE_FLAG);                     /* reserved */
        paddr += BIT(hm_PageBits);
    }
}

void init_kernel_vspace(const struct image_info *kernel_img_info)
{
    ulong_t map_size;
    ulong_t pt_num;
    uint32_t i;
    pte_array_t *kernel_pt = NULL;
    vaddr_t *kernel_pud = (vaddr_t *)(uintptr_t)((vaddr_t)(uintptr_t)_image_base_addr - \
                           BOOT_OFFSET + KERNEL_LEVEL1_OFFSET);

    pde_t (*tmp_pmd)[BIT(hm_PageDirIndexBits)] = g_kernel_pmd;
    vaddr_t vptr;
    paddr_t paddr;

    if (kernel_img_info == NULL) {
        klog(DEBUG_INFO, "kernel_img_info == NULL\n");
        return;
    }
    ASSERT(g_plat_cfg.phys_region_size % BIT(hm_PageBits) == 0);
    ASSERT(kernel_img_info->virt_region_start % BIT(hm_PageBits) == 0);
    ASSERT(kernel_img_info->phys_region_start % BIT(hm_PageBits) == 0);
    ASSERT(IS_ALIGNED(KERNEL_LOAD_OFFSET, hm_PageBits));

    map_size = g_plat_cfg.phys_region_size > BIT(hm_HugePageBits) ? BIT(hm_HugePageBits) : g_plat_cfg.phys_region_size;
    map_size = (map_size > ELFLOADER_MAP_SIZE) ? ELFLOADER_MAP_SIZE : map_size;

    vaddr_t first_vaddr = kernel_img_info->virt_region_start - KERNEL_LOAD_OFFSET;
    paddr_t first_paddr = kernel_img_info->phys_region_start - KERNEL_LOAD_OFFSET;
    vaddr_t end_vaddr = first_vaddr + map_size;
    pt_num = PT_ARRAY_SIZE;

    kernel_pt = (pte_array_t *)(uintptr_t)(_image_base_addr - BOOT_OFFSET + map_size - \
                 pt_num * BIT(hm_PageBits) - g_plat_cfg.shmem_size);

    memset(kernel_pt, 0, pt_num * BIT(hm_PageBits));

    klog(DEBUG_LOG, "kernel pud %p, pmd %p\n", kernel_pud, g_kernel_pmd);

    klog(DEBUG_LOG, "mem size %lu, mapped size %lu : paddr start %lx, paddr_end %lx, vaddr_start %lx, vaddr end %lx\n",
         (unsigned long)g_plat_cfg.phys_region_size, map_size, (unsigned long)first_paddr,
         (unsigned long)(first_paddr + map_size), (unsigned long)first_vaddr, (unsigned long)end_vaddr);
    klog(DEBUG_LOG, "pt array addr %p, end %p, pt page num %lu\n", kernel_pt,
         (void *)((uintptr_t)kernel_pt + pt_num * BIT(hm_PageBits)), pt_num);

    /* set pmd to pud */
    for (i = GET_PUD_INDEX(first_vaddr); i <= GET_PUD_INDEX(end_vaddr); i++) {
        if (kernel_pud[i] == 0) {
            kernel_pud[i] = (elfloader_kaddr_to_paddr((vaddr_t)(uintptr_t)tmp_pmd) | MMU_VALID_TABLE_FLAG);
            tmp_pmd++;
        }
    }

    for (vptr = ROUND_DOWN(first_vaddr, PD_INDEX_OFFSET),
         paddr = ROUND_DOWN(first_paddr, PD_INDEX_OFFSET),
         i = 0;
         vptr < end_vaddr; vptr += BIT(PD_INDEX_OFFSET), paddr += BIT(PD_INDEX_OFFSET), i++) {
         pde_t *pmd_item = (pde_t *)(uintptr_t)&(kernel_pud[GET_PUD_INDEX(vptr)]);
         paddr_t pmd_paddr =  pde_pde_small_ptr_get_pt_base_address(pmd_item);
         pgtable_set(vptr, paddr, (pde_t *)(uintptr_t)elfloader_paddr_to_vaddr(pmd_paddr), &kernel_pt[i]);
    }
    invalidate_tlb();
}

uint64_t get_kaslr_pg_size(uint64_t map_size)
{
    uint32_t page_num = map_size / BIT(hm_PageBits);
    return (page_num * (1<<PMD_ORDER));
}
#else
void init_kernel_vspace(struct image_info *kernel_img_info)
{
    ulong_t i;
    uint64_t map_size;
    vaddr_t *kernel_pgd = (vaddr_t *)(uintptr_t)((vaddr_t)(uintptr_t)_image_base_addr - \
                           BOOT_OFFSET + KERNEL_LEVEL0_OFFSET);

    vaddr_t *kernel_pud = (vaddr_t *)(uintptr_t)((vaddr_t)(uintptr_t)_image_base_addr - \
                           BOOT_OFFSET + KERNEL_LEVEL1_OFFSET);

    paddr_t kernel_pud_phy = elfloader_kaddr_to_paddr((vaddr_t)(uintptr_t)kernel_pud);
    paddr_t kernel_pmd_phy = elfloader_kaddr_to_paddr((vaddr_t)(uintptr_t)g_kernel_pmd);

    if (kernel_img_info == NULL) {
        klog(DEBUG_INFO, "kernel_img_info == NULL\n");
        return;
    }
    vaddr_t first_vaddr = kernel_img_info->virt_region_start - KERNEL_LOAD_OFFSET;
    paddr_t first_paddr = kernel_img_info->phys_region_start - KERNEL_LOAD_OFFSET;

    klog(DEBUG_INFO, "Setup kernel vspace: \n");
    klog(DEBUG_LOG, "kernel pgd = %p\n", kernel_pgd);
    klog(DEBUG_LOG, "kernel pud = %p\n", kernel_pud);
    klog(DEBUG_LOG, "kernel pmd = %p\n", g_kernel_pmd);

    kernel_pgd[GET_PGD_INDEX(first_vaddr)] = ((uintptr_t)kernel_pud_phy) | MMU_VALID_TABLE_FLAG; /* its a page table */
    kernel_pud[GET_PUD_INDEX(first_vaddr)] = ((uintptr_t)kernel_pmd_phy) | MMU_VALID_TABLE_FLAG; /* its a page table */

    uint32_t pmd_start = (uint32_t)(GET_PD_INDEX(first_vaddr));
    klog(DEBUG_LOG,
        "kernel first_vaddr = %llx, first_paddr = %llx\n, \
        virt_region_start = %llx, virt_region_end = %llx\n \
        phys_region_start = %llx, phys_region_end = %llx \n",
        first_vaddr, first_paddr, kernel_img_info->virt_region_start, kernel_img_info->virt_region_end,
        kernel_img_info->phys_region_start, kernel_img_info->phys_region_end);
    map_size = g_plat_cfg.phys_region_size;
    map_size = (map_size > ELFLOADER_MAP_SIZE) ? ELFLOADER_MAP_SIZE : map_size;
    uint32_t pmd_end = (ALIGN_UP(map_size, BIT(hm_LargePageBits)) >> hm_LargePageBits) + pmd_start;
    /* Note: Because first_vaddr is align with 1G for NON-KASLR, pmd_start is zero, here we should not crossing puds */
    pmd_end = (pmd_end > BIT(hm_PageDirIndexBits) ? BIT(hm_PageDirIndexBits) : pmd_end);
    klog(DEBUG_INFO, "kernel pmd_start = %u, pmd_end = %u\n", pmd_start, pmd_end);
    for (i = pmd_start; i < pmd_end; i++)
        g_kernel_pmd[i] = (((i - pmd_start) << hm_LargePageBits) + first_paddr) | PTE_AF_ATTR /* access flag */
#if CONFIG_MAX_NUM_NODES > 1
                        | MEM_SHARE_ATTR /* make sure the shareability is the same as the kernel's */
#endif
                        | PTE_ATTRIDX(MEM_MT_NORMAL) /* MT_NORMAL memory */
                        | MMU_BLOCK_FLAG;  /* 2M block */
    invalidate_tlb();
}
#endif
