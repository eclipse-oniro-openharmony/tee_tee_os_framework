/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2001-2020. All rights reserved.
 * Description: This program is used to build sec iommu page table
 * Author: jianfujian
 * Create: 2001-1-1
 */

#ifndef _SMMU_PAGE_DEF_H
#define _SMMU_PAGE_DEF_H

#include <register_ops.h>
#include <sre_typedef.h>

#define SMMU_PTRS_PER_PGD 4
#define SMMU_PTRS_PER_PMD 512
#define SMMU_PTRS_PER_PTE 512
#define SMMU_PAGE_SHIFT 12
#define PAGE_TABLE_ADDR_MASK (0xFFFFFFFUL << SMMU_PAGE_SHIFT)

#define CONFIG_PGTABLE_LEVELS 3
#define bit(n) (1ULL << (n))
#define VA_BITS 32
#define PAGE_SHIFT 12
#define SMMU_PAGE_SIZE (1UL << PAGE_SHIFT)
#define smmu_page_align(addr) ALIGN(addr, SMMU_PAGE_SIZE)

#define PTRS_PER_PTE (1UL << (PAGE_SHIFT - 3))

#define SMMU_PGDIR_SHIFT ((PAGE_SHIFT - 3) * CONFIG_PGTABLE_LEVELS + 3)
#define SMMU_PGDIR_SIZE (1UL << SMMU_PGDIR_SHIFT)
#define SMMU_PGDIR_MASK (~(SMMU_PGDIR_SIZE - 1))

#define SMMU_PMDIR_SHIFT 21
#define SMMU_PMDIR_SIZE bit(SMMU_PMDIR_SHIFT)
#define SMMU_PMDIR_MASK (~(SMMU_PMDIR_SIZE - 1))
#define SMMU_PGD_TYPE (bit(0) | bit(1))
#define SMMU_PMD_TYPE (bit(0) | bit(1))
#define SMMU_PTE_TYPE (bit(0) | bit(1))

#define PTE_SHIFT ((PAGE_SHIFT - 3) * 1 + 3)
#define SMMU_PTE_SIZE (1UL << PTE_SHIFT)
#define PTE_MASK (~(PTE_SIZE - 1))

#define PTE_TYPE_MASK 3
#define PTE_TABLE_BIT bit(1)
#define PTE_TYPE_PAGE 3

#define PMD_TYPE_SECT 1
#define PMD_SECT_VALID 1
#define PMD_SECT_PROT_NONE bit(58)
#define PMD_SECT_USER bit(6)   /* AP[1] */
#define PMD_SECT_RDONLY bit(7) /* AP[2] */
#define PMD_SECT_S (3UL << 8)
#define PMD_SECT_AF bit(10)
#define PMD_SECT_NG bit(11)
#define PMD_SECT_PXN bit(53)
#define PMD_SECT_UXN bit(54)
#define PMD_SECT_NS bit(5)

#define SMMU_PGD_NS bit(63)
#define SMMU_PMD_NS bit(63)
#define SMMU_PTE_NS bit(5)

#define SMMU_PTE_PXN bit(53)       /* Privileged XN */
#define SMMU_PTE_UXN bit(54)      /* User XN */
#define SMMU_PTE_USER bit(6)              /* AP[1] */
#define SMMU_PTE_RDONLY bit(7)            /* AP[2] */
#define SMMU_PTE_SHARED (bit(8) | bit(9)) /* SH[1:0], inner shareable */
#define SMMU_PTE_AF bit(10)               /* Access Flag */
#define SMMU_PTE_NG bit(11)               /* nG */
#define smmu_pte_attrindx(t) ((t) << 2)

/*
 * Memory types available.
 */
#define MT_NORMAL 0
#define MT_NORMAL_CACHE 1
#define MT_NORMAL_NC 3
#define MT_DEVICE_NGNRE 3 /* smmuv2 do not support DEVICE memory */

#define SMMU_PAGE_DEFAULT (SMMU_PTE_TYPE | SMMU_PTE_AF | SMMU_PTE_SHARED)

#define SMMU_PROT_DEVICE_NGNRE                                                 \
	(SMMU_PAGE_DEFAULT | SMMU_PTE_PXN | SMMU_PTE_UXN |                     \
		smmu_pte_attrindx(MT_DEVICE_NGNRE))
#define SMMU_PROT_NORMAL_CACHE                                                 \
	(SMMU_PAGE_DEFAULT | SMMU_PTE_PXN | SMMU_PTE_UXN |                     \
		smmu_pte_attrindx(MT_NORMAL_CACHE))
#define SMMU_PROT_NORMAL_NC                                                    \
	(SMMU_PAGE_DEFAULT | SMMU_PTE_PXN | SMMU_PTE_UXN |                     \
		smmu_pte_attrindx(MT_NORMAL_NC))
#define SMMU_PROT_NORMAL (SMMU_PAGE_DEFAULT | smmu_pte_attrindx(MT_NORMAL_NC))

#define SMMU_PAGE_READWRITE                                                    \
	(SMMU_PAGE_DEFAULT | SMMU_PTE_USER | SMMU_PTE_NG | SMMU_PTE_PXN |      \
		SMMU_PTE_UXN)
#define SMMU_PAGE_READONLY                                                     \
	(SMMU_PAGE_DEFAULT | SMMU_PTE_USER | SMMU_PTE_RDONLY | SMMU_PTE_NG |   \
		SMMU_PTE_PXN | SMMU_PTE_UXN)
#define SMMU_PAGE_READONLY_EXEC                                                \
	(SMMU_PAGE_DEFAULT | SMMU_PTE_USER | SMMU_PTE_NG)

/*
 *  AttrIndx[2:0] encoding (mapping attributes defined in the MAIR* registers).
 */
#define pmd_attrindx(t) ((t) << 2)
#define PMD_ATTRINDX (7U << 2)

#define PROT_SECT_DEFAULT (PMD_TYPE_SECT | PMD_SECT_AF | PMD_SECT_S)

#define PROT_SECT_DEVICE_NGNRE                                                 \
	(PROT_SECT_DEFAULT | PMD_SECT_PXN | PMD_SECT_UXN |                     \
		pmd_attrindx(MT_DEVICE_NGNRE))
#define PROT_SECT_NORMAL                                                       \
	(PROT_SECT_DEFAULT | PMD_SECT_PXN | PMD_SECT_UXN |                     \
		pmd_attrindx(MT_NORMAL))
#define PROT_SECT_NORMAL_EXEC                                                  \
	(PROT_SECT_DEFAULT | PMD_SECT_UXN | pmd_attrindx(MT_NORMAL))

#define PROT_DEFAULT                                                           \
	(PTE_TYPE_PAGE | PMD_SECT_PXN | PMD_SECT_UXN |                         \
		pmd_attrindx(MT_NORMAL) | PMD_SECT_USER)

static inline u64 smmu_pgd_addr_end_lpae(u64 addr, u64 end)
{
	u64 boundary = (addr + SMMU_PGDIR_SIZE) & SMMU_PGDIR_MASK;

	return (boundary < end) ? boundary : end;
}

static inline u32 smmu_pmd_addr_end_lpae(u32 addr, u32 end)
{
	u32 boundary = (addr + SMMU_PMDIR_SIZE) & SMMU_PMDIR_MASK;

	return (boundary < end) ? boundary : end;
}

#endif
