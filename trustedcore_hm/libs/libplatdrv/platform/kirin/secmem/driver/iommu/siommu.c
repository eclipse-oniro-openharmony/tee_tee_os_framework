/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2001-2020. All rights reserved.
 * Description: This program is used to build sec iommu page table
 * Author: jianfujian
 * Create: 2001-1-1
 */

#include "siommu.h"
#include "legacy_mem_ext.h"
#include "drv_mem.h"
#include "drv_cache_flush.h"
#include "drv_module.h"
#include "secmem.h"
#include "secmem_priv.h"
#include "securec.h"
#include "mem_ops.h"
#include "mem_page_ops.h"
#include "tee_log.h"

#define smmu_pte_index(addr)                                                   \
	(((addr) >> SMMU_PAGE_SHIFT) & (SMMU_PTRS_PER_PTE - 1))
#define smmu_pmd_index(addr)                                                   \
	(((addr) >> SMMU_PMDIR_SHIFT) & (SMMU_PTRS_PER_PMD - 1))
#define smmu_pgd_index(addr)                                                   \
	(((addr) >> SMMU_PGDIR_SHIFT) & (SMMU_PTRS_PER_PGD - 1))

#define pool_pa(va, va_base, phys_base) ((va) - (va_base) + (phys_base))
#define pool_va(pa, pa_base, va_base) ((pa) - (pa_base) + (va_base))

#define MIN_PMD_NR  4
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define isb() asm volatile("isb" : : : "memory")
#define dmb(opt) asm volatile("dmb " #opt : : : "memory")
#define dsb(opt) asm volatile("dsb " #opt : : : "memory")

#define WORD_MASK  0xFFFFFFFF
#define BITS_PER_WORD   32

typedef u64 smmu_pgd_t;
typedef u64 smmu_pmd_t;
typedef u64 smmu_pte_t;

struct smmu_addr_pair {
	u64 addr;
	u64 end;
	u64 paddr;
};

static inline u64 smmu_pgd_none_lpae(smmu_pgd_t pgd)
{
	return !(pgd ? pgd : 0);
}

static inline u64 smmu_pmd_none_lpae(smmu_pmd_t pmd)
{
	return !(pmd ? pmd : 0);
}

/* fill the pgd entry, pgd value must be 64bit */
static inline void smmu_set_pgd_lpae(smmu_pgd_t *pgdp, u64 pgd_ent)
{
	*pgdp = pgd_ent;
	dsb(ishst);
	isb();
}

/* fill the pmd entry, pgd value must be 64bit */
static inline void smmu_set_pmd_lpae(smmu_pgd_t *pmdp, u64 pmd_ent)
{
	*pmdp = pmd_ent;
	dsb(ishst);
	isb();
}

static inline void smmu_pmd_populate_lpae(smmu_pmd_t *pmdp, u64 ptep, u64 prot)
{
	smmu_set_pmd_lpae(pmdp, ptep | prot);
}

static inline void smmu_pgd_populate_lpae(smmu_pgd_t *pgdp, u64 pmdp, u64 prot)
{
	smmu_set_pgd_lpae(pgdp, pmdp | prot);
}

/* Find an entry in the second-level page table.. */
static inline smmu_pmd_t smmu_pmd_page_vaddr_lpae(const smmu_pmd_t *pgd)
{
	return *pgd & PAGE_TABLE_ADDR_MASK;
}

/* Find an entry in the third-level page table.. */
static inline smmu_pte_t smmu_pte_page_vaddr_lpae(const smmu_pte_t *pmd)
{
	return *pmd & PAGE_TABLE_ADDR_MASK;
}

static inline s32 pte_is_valid_lpae(u64 pte)
{
	return (pte & SMMU_PTE_TYPE) ? 1 : 0;
}

/* DRM map */
static u64 set_pte_prot_lpae(u32 prot)
{
	u64 pteval = SMMU_PTE_TYPE;

	if (prot) {
		if (prot & IOMMU_SEC) {
			pteval |= SMMU_PROT_NORMAL_CACHE | SMMU_PAGE_READWRITE;
			pteval &= ~SMMU_PTE_NS;
		}
	} else {
		pteval |= SMMU_PROT_NORMAL | SMMU_PTE_NS;
#ifdef TEE_SUPPORT_SMMUV3
		pteval |= SMMU_PAGE_READWRITE;
#endif
	}

	return pteval;
}

static s32 smmu_pte_map_lpae(const struct smmu_domain *sdomain, u32 iova,
				u32 end, u64 paddr, u32 prot)
{
	u64 *pte_base = NULL;
	u64 *pmd_base = NULL;
	u64 pteval;

	pmd_base = sdomain->pmd + smmu_pgd_index(iova) * SMMU_PTRS_PER_PMD;
	if (!prot) {
		pmd_base[smmu_pmd_index(iova)] =
			sdomain->pte_phys + (SZ_4K * smmu_pmd_index(iova));
		pmd_base[smmu_pmd_index(iova)] |= SMMU_PMD_TYPE;
#ifdef TEE_SUPPORT_SMMUV3
		pmd_base[smmu_pmd_index(iova)] &= ~SMMU_PMD_NS;
#else
		pmd_base[smmu_pmd_index(iova)] |= SMMU_PMD_NS;
#endif
	} else if (prot & IOMMU_SEC) {
		pmd_base[smmu_pmd_index(iova)] =
			sdomain->pte_phys + (SZ_4K * smmu_pmd_index(iova));
		pmd_base[smmu_pmd_index(iova)] |= SMMU_PMD_TYPE;
	}

	pteval = set_pte_prot_lpae(prot);
	pte_base = sdomain->pte +
		smmu_pgd_index(iova) * SMMU_PTRS_PER_PMD * SMMU_PTRS_PER_PTE +
		smmu_pmd_index(iova) * SMMU_PTRS_PER_PTE;
	do {
		if (!pte_is_valid_lpae(pte_base[smmu_pte_index(iova)])) {
			pte_base[smmu_pte_index(iova)] = paddr | pteval;
		} else {
			tloge("map the same address more times! iova = 0x%x\n",
				iova);
			ddrc_ca_rd_info_dump();
			return -EINVAL;
		}
	} while (paddr += SMMU_PAGE_SIZE, iova += SMMU_PAGE_SIZE, iova < end);

	return 0;
}

static s32 smmu_pmd_map_lpae(const struct smmu_domain *sdomain, u32 iova,
				u32 end, u64 paddr, u32 prot)
{
	s32 nr;
	s32 ret;
	u32 next;

	nr = smmu_pgd_index(iova);
	nr = min(nr, MIN_PMD_NR);

	if (!prot) {
#ifdef TEE_SUPPORT_SMMUV3
		(sdomain->pgd)[nr] &= ~SMMU_PGD_NS;
#else
		(sdomain->pgd)[nr] |= SMMU_PGD_NS;
#endif
		(sdomain->pgd)[nr] |= sdomain->pmd_phys | SMMU_PGD_TYPE;
	}

	if (prot & IOMMU_SEC) {
		(sdomain->pgd)[nr] &= ~SMMU_PGD_NS;
		(sdomain->pgd)[nr] |= sdomain->pmd_phys | SMMU_PGD_TYPE;
	}

	do {
		next = smmu_pmd_addr_end_lpae(iova, end);
		ret = smmu_pte_map_lpae(sdomain, iova, next, paddr, prot);
		if (ret)
			return ret;
		paddr += (next - iova);
		iova = next;
	} while (iova < end);

	return 0;
}

static s32 smmu_pdg_map_lpae(const struct smmu_domain *sdomain, u64 paddr,
				u32 iova, u32 size, u32 prot)
{
	if (iova >= iova + size)
		return -EINVAL;

	return smmu_pmd_map_lpae(sdomain, iova, iova + size, paddr, prot);
}

s32 hisi_smmu_create_map(const struct smmu_domain *sdomain, u64 paddr, u32 iova,
			 u32 size, u32 prot)
{
	/* page alian paddr first */
	s32 ret;

	paddr = ((paddr >> PAGE_SHIFT) << PAGE_SHIFT);
	ret = smmu_pdg_map_lpae(sdomain, paddr, iova, size, prot);
#ifdef SMMU_MAP_DEBUG
	if (!ret)
		hisi_dump_pgtable(sdomain, iova, SZ_1M);
#endif
	return ret;
}

static u32 smmu_clear_pte_lpae(const struct smmu_domain *sdomain, u32 iova,
				u32 end)
{
	u32 size;
	u64 *pte_base = NULL;

	if (end <= iova)
		return 0;

	size = end - iova;
	pte_base = sdomain->pte +
		smmu_pgd_index(iova) * SMMU_PTRS_PER_PMD * SMMU_PTRS_PER_PTE +
		smmu_pmd_index(iova) * SMMU_PTRS_PER_PTE;

	if (memset_s(&pte_base[smmu_pte_index(iova)],
		    sizeof(u64) * (size >> SMMU_PAGE_SHIFT), 0x0,
		    sizeof(u64) * (size >> SMMU_PAGE_SHIFT))) {
		tloge("%s memset failed\n", __func__);
		return 0;
	}

	return size;
}

static u32 smmu_clear_pmd_lpae(const struct smmu_domain *sdomain,
				u32 iova, u32 end)
{
	u32 next;
	u32 size = 0;

	do {
		next = smmu_pmd_addr_end_lpae(iova, end);
		size += smmu_clear_pte_lpae(sdomain, iova, next);
		iova = next;
	} while (iova < end);

	return size;
}

s32 hisi_smmu_destory_map(const struct smmu_domain *sdomain,
				u32 iova, u32 size)
{
	u32 end;
	u32 next;
	u32 unmap_size = 0;

	if (!sdomain)
		return -EINVAL;

	end = iova + size;
	if (end <= iova)
		return -EINVAL;

	do {
		next = smmu_pgd_addr_end_lpae(iova, end);
		unmap_size += smmu_clear_pmd_lpae(sdomain, iova, next);
		iova = next;
	} while (iova < end);

	return (unmap_size == size) ? 0 : -EINVAL;
}

#ifdef SECMEM_UT
static void print_pte_within_one_pmd(const struct smmu_domain *sdomain,
		u32 iova, u32 size)
{
	u32 pte_h;
	u32 pte_l;
	u64 *pte_base = NULL;

	pte_base = sdomain->pte +
		smmu_pgd_index(iova) * SMMU_PTRS_PER_PMD * SMMU_PTRS_PER_PTE +
		smmu_pmd_index(iova) * SMMU_PTRS_PER_PTE;
	do {
		pte_h = (u32)((pte_base[smmu_pte_index(iova)] >>
						BITS_PER_WORD) & WORD_MASK);
		pte_l = (u32)((pte_base[smmu_pte_index(iova)]) & WORD_MASK);
		tloge("pte_h[%u]:0x%x, pte_l[%u]:0x%x\n", smmu_pte_index(iova),
			pte_h, smmu_pte_index(iova), pte_l);

		/* overflow */
		if (iova + SMMU_PMDIR_SIZE < iova)
			return;
		iova += SMMU_PTE_SIZE;

		if (size < SMMU_PMDIR_SIZE)
			return;
		size -= SMMU_PTE_SIZE;
	} while (size);
}

void hisi_dump_pgtable(const struct smmu_domain *sdomain, u32 iova, u32 size)
{
	u64 *pmd_base = NULL;
	u32 pgd_h, pgd_l, pmd_h, pmd_l;

	if (!sdomain) {
		tloge("sdomain is null\n");
		return;
	}
	iova = smmu_page_align(iova);
	size = smmu_page_align(size);

	pgd_h = (u32)(((sdomain->pgd)[smmu_pgd_index(iova)] >>
						BITS_PER_WORD) & WORD_MASK);
	pgd_l = (u32)(((sdomain->pgd)[smmu_pgd_index(iova)]) & WORD_MASK);

	tloge("pgd_h[%u]:0x%x, pgd_l[%u]:0x%x\n", smmu_pgd_index(iova), pgd_h,
		smmu_pgd_index(iova), pgd_l);

	do {
		pmd_base = sdomain->pmd +
				smmu_pgd_index(iova) * SMMU_PTRS_PER_PMD;
		pmd_h = (u32)((pmd_base[smmu_pmd_index(iova)] >>
						BITS_PER_WORD) & WORD_MASK);
		pmd_l = (u32)((pmd_base[smmu_pmd_index(iova)]) & WORD_MASK);

		tloge("pmd_h[%u]:0x%x, pmd_l[%u]:0x%x\n", smmu_pmd_index(iova),
			pmd_h, smmu_pmd_index(iova), pmd_l);
		if (size >= SMMU_PMDIR_SIZE) {
			print_pte_within_one_pmd(sdomain,
							iova, SMMU_PMDIR_SIZE);
		} else {
			print_pte_within_one_pmd(sdomain, iova, size);
			break;
		}
		/* overflow */
		if (iova + SMMU_PMDIR_SIZE < iova)
			return;
		iova += SMMU_PMDIR_SIZE;

		size -= SMMU_PMDIR_SIZE;
	} while (size);
}
#endif

struct smmu_domain *hisi_siommu_init(u32 pgtable_addr, u32 pgtable_size)
{
	u32 siommu_pgd_phys;
	u32 siommu_pmd_phys;
	u32 siommu_pte_phys;
	struct smmu_domain *sdomain = NULL;

	if (!pgtable_addr || pgtable_size <= SZ_8K)
		return NULL;

	siommu_pgd_phys = pgtable_addr;
	siommu_pmd_phys = siommu_pgd_phys + SZ_4K;
	siommu_pte_phys = siommu_pmd_phys + SZ_4K;

	sdomain = SRE_MemAlloc(OS_MID_SYS,
		OS_MEM_DEFAULT_FSC_PT, sizeof(*sdomain));
	if (!sdomain) {
		tloge("sdomain alloc failed\n");
		return NULL;
	}

	if (sre_mmap(siommu_pgd_phys, SZ_4K, (u32 *)(uintptr_t)&(sdomain->pgd), secure,
		    non_cache) ||
		memset_s(sdomain->pgd, SZ_4K, 0, SZ_4K)) {
		tloge("PGD mmap fail!!\n");
		goto free_mem;
	}

	if (sre_mmap(siommu_pmd_phys, SZ_4K, (u32 *)(uintptr_t)&(sdomain->pmd), secure,
		    non_cache) ||
		memset_s(sdomain->pmd, SZ_4K, 0, SZ_4K)) {
		tloge("PMD mmap fail!!\n");
		goto unmap_pgd;
	}

	if (sre_mmap(siommu_pte_phys, pgtable_size - SZ_8K,
		    (u32 *)(uintptr_t)&(sdomain->pte), secure, non_cache) ||
		memset_s(sdomain->pte, pgtable_size - SZ_8K, 0,
			pgtable_size - SZ_8K)) {
		tloge("pte mmap fail!!\n");
		goto unmap_pmd;
	}

	sdomain->pgtable_addr = pgtable_addr;
	sdomain->pgtable_size = pgtable_size;
	sdomain->pgd_phys = siommu_pgd_phys;
	sdomain->pmd_phys = siommu_pmd_phys;
	sdomain->pte_phys = siommu_pte_phys;

	return sdomain;

unmap_pmd:
	(void)sre_unmap((uintptr_t)(sdomain->pmd), SZ_4K);
unmap_pgd:
	(void)sre_unmap((uintptr_t)(sdomain->pgd), SZ_4K);
free_mem:
	SRE_MemFree(OS_MID_SYS, sdomain);
	return NULL;
}

static u64 smmu_build_pteval(int tprot, u64 attr)
{
	u64 pteval = attr;
	unsigned int prot = (unsigned int)tprot;

	if (!prot) {
		pteval |= SMMU_PROT_NORMAL;
		pteval |= SMMU_PTE_NS;
		return pteval;
	}

	if (prot & IOMMU_DEVICE) {
		pteval |= SMMU_PROT_DEVICE_NGNRE;
	} else {
		if (prot & IOMMU_CACHE)
			pteval |= SMMU_PROT_NORMAL_CACHE;
		else
			pteval |= SMMU_PROT_NORMAL_NC;

		if ((prot & IOMMU_READ) && (prot & IOMMU_WRITE))
			pteval |= SMMU_PAGE_READWRITE;
		else if ((prot & IOMMU_READ) && !(prot & IOMMU_WRITE))
			pteval |= SMMU_PAGE_READONLY;
		else
			tloge("you do not set read attribute!");

		if (prot & IOMMU_EXEC) {
			pteval |= SMMU_PAGE_READONLY_EXEC;
			pteval &= ~(SMMU_PTE_PXN | SMMU_PTE_UXN);
		}
	}

	if (prot & IOMMU_SEC)
		pteval &= ~SMMU_PTE_NS;
	else
		pteval |= SMMU_PTE_NS;

	return pteval;
}

/* sec map */
static int smmu_pte_range(const struct smmu_domain *sdomain, smmu_pmd_t *ppmd,
				struct smmu_addr_pair addr_pair, int prot)
{
	smmu_pte_t *ppte = NULL;
	smmu_pte_t *ptep = NULL;
	smmu_pte_t start;
	u64 pteval = SMMU_PTE_TYPE;
	u64 pte_phys;

	if (!smmu_pmd_none_lpae(*ppmd))
		goto pte_ready;

	/* Allocate a new set of tables */
	ppte = (smmu_pte_t *)(uintptr_t)gen_pool_alloc(sdomain->pool, PAGE_SIZE);
	if (!ppte) {
		tloge("%s: alloc page fail\n", __func__);
		return -ENOMEM;
	}

	pte_phys = pool_pa((u32)(uintptr_t)ppte, sdomain->va_base, sdomain->pgtable_addr);
	smmu_pmd_populate_lpae(ppmd, pte_phys, SMMU_PMD_TYPE | SMMU_PMD_NS);

pte_ready:
	*ppmd &= ~SMMU_PMD_NS;

	start = smmu_pte_page_vaddr_lpae(ppmd);
	ptep = (smmu_pte_t *)(uintptr_t)(u32)pool_va(
		start, sdomain->pgtable_addr, sdomain->va_base);
	ppte = ptep + smmu_pte_index(addr_pair.addr);

	pteval = smmu_build_pteval(prot, pteval);
	do {
		*ppte = (u64)(addr_pair.paddr | pteval);
		ppte++;
		addr_pair.paddr += SMMU_PAGE_SIZE;
		addr_pair.addr += SMMU_PAGE_SIZE;
	} while (addr_pair.addr < addr_pair.end);

	dsb(ishst);
	isb();

	return 0;
}

static int smmu_pmd_range(const struct smmu_domain *sdomain, smmu_pgd_t *ppgd,
				struct smmu_addr_pair addr_pair, int prot)
{
	smmu_pmd_t *pmdp = NULL;
	smmu_pmd_t *ppmd =  NULL;
	smmu_pmd_t start;
	u64 next, pmd_phys;
	int ret;
	struct smmu_addr_pair new;

	if (!smmu_pgd_none_lpae(*ppgd))
		goto pmd_ready;

	/* Allocate a new set of tables */
	ppmd = (smmu_pmd_t *)(uintptr_t)gen_pool_alloc(sdomain->pool, PAGE_SIZE);
	if (!ppmd) {
		tloge("%s: alloc page fail\n", __func__);
		return -ENOMEM;
	}
	pmd_phys = pool_pa((u32)(uintptr_t)ppmd, sdomain->va_base, sdomain->pgtable_addr);
	smmu_pgd_populate_lpae(ppgd, pmd_phys, SMMU_PGD_TYPE | SMMU_PGD_NS);

pmd_ready:
	*ppgd &= ~SMMU_PGD_NS;

	start = smmu_pmd_page_vaddr_lpae(ppgd);
	pmdp = (smmu_pmd_t *)(uintptr_t)pool_va(
		start, sdomain->pgtable_addr, sdomain->va_base);
	ppmd = pmdp + smmu_pmd_index(addr_pair.addr);

	do {
		next = smmu_pmd_addr_end_lpae(addr_pair.addr, addr_pair.end);
		new.addr = addr_pair.addr;
		new.end = next;
		new.paddr = addr_pair.paddr;
		ret = smmu_pte_range(sdomain, ppmd, new, prot);
		if (ret)
			return ret; /* no need to free gen pool */
		addr_pair.paddr += (next - addr_pair.addr);
		addr_pair.addr = next;
	} while (ppmd++, addr_pair.addr < addr_pair.end);

	return 0;
}

int smmu_handle_mapping(const struct smmu_domain *sdomain, u64 va, u64 pa,
				u64 sz, int prot)
{
	int ret;
	smmu_pgd_t *pgd = NULL;
	smmu_pgd_t *ppgd = NULL;
	u64 iova, end, next;
	struct smmu_addr_pair addr_pair;

	if (!sdomain || !pa || !sz) /* smmu can support iova = 0 */
		return -EINVAL;

	pgd = sdomain->pgd;
	ppgd = pgd + smmu_pgd_index(va);
	iova = va;
	addr_pair.paddr = pa;
	end = iova + sz;
	if (end <= iova)
		return -EINVAL;
	do {
		next = smmu_pgd_addr_end_lpae(iova, end);
		addr_pair.addr = iova;
		addr_pair.end = next;
		ret = smmu_pmd_range(sdomain, ppgd, addr_pair, prot);
		if (ret || next < iova)
			goto out_unlock;
		addr_pair.paddr += next - iova;
		iova = next;
	} while (ppgd++, iova < end);

out_unlock:
	return ret;
}

static void smmu_clear_pte(const struct smmu_domain *sdomain, smmu_pgd_t *pmdp,
				u64 iova, u64 end)
{
	smmu_pte_t *ptep = NULL;
	smmu_pte_t *ppte = NULL;
	smmu_pte_t pte_phys;
	u64 size;

	if (end <= iova)
		return;

	size = end - iova;
	pte_phys = smmu_pte_page_vaddr_lpae(pmdp);
	ptep = (smmu_pte_t *)(uintptr_t)(u32)pool_va(
		pte_phys, sdomain->pgtable_addr, sdomain->va_base);
	ppte = ptep + smmu_pte_index(iova);

	if (!!size)
		(void)memset_s(ppte, (size / SMMU_PAGE_SIZE) * sizeof(*ppte), 0,
			(size / SMMU_PAGE_SIZE) * sizeof(*ppte));
}

static u64 smmu_clear_pmd(const struct smmu_domain *sdomain, smmu_pgd_t *pgdp,
				u64 iova, u64 end)
{
	smmu_pmd_t *pmdp = NULL;
	smmu_pmd_t *ppmd = NULL;
	smmu_pmd_t pmd_phys;
	u64 next, size;

	if (end <= iova)
		return 0;

	size = end - iova;
	pmd_phys = smmu_pmd_page_vaddr_lpae(pgdp);
	pmdp = (smmu_pmd_t *)(uintptr_t)(u32)pool_va(
		pmd_phys, sdomain->pgtable_addr, sdomain->va_base);
	ppmd = pmdp + smmu_pmd_index(iova);

	do {
		next = smmu_pmd_addr_end_lpae(iova, end);
		smmu_clear_pte(sdomain, ppmd, iova, next);
		iova = next;
	} while (ppmd++, iova < end);

	return size;
}

u32 smmu_handle_unmapping(const struct smmu_domain *sdomain, u64 iova, u64 size)
{
	smmu_pgd_t *pgdp = NULL;
	u64 end;
	u64 next;
	u64 unmap_size = 0;

	if (!sdomain || !size) /* smmu can support iova = 0 */
		return 0;

	iova = smmu_page_align(iova);
	size = smmu_page_align(size);
	pgdp = (smmu_pgd_t *)sdomain->pgd;
	end = iova + size;
	if (end <= iova)
		return 0;
	pgdp += smmu_pgd_index(iova);

	do {
		next = smmu_pgd_addr_end_lpae(iova, end);
		unmap_size += smmu_clear_pmd(sdomain, pgdp, iova, next);
		iova = next;
	} while (pgdp++, iova < end);

	return (u32)unmap_size;
}

struct smmu_domain *siommu_domain_alloc(u32 pgtable_addr, u32 pgtable_size)
{
	struct smmu_domain *sdomain = NULL;
	u32 vaddr;
	int ret;

	if (!pgtable_addr || !pgtable_size || pgtable_size > SZ_4M)
		return NULL;

	if (pgtable_addr + pgtable_size <= pgtable_addr)
		return NULL;

	sdomain = SRE_MemAlloc(OS_MID_SYS,
		OS_MEM_DEFAULT_FSC_PT, sizeof(*sdomain));
	if (!sdomain) {
		tloge("sdomain alloc failed\n");
		return NULL;
	}
	(void)memset_s(sdomain, sizeof(*sdomain), 0, sizeof(*sdomain));

	/* map pgtable section to secos */
	if (sre_mmap(pgtable_addr, pgtable_size, &vaddr, secure, non_cache)) {
		tloge("pgtable map failed\n");
		goto free_domain;
	}
	(void)memset_s((void *)(uintptr_t)vaddr, pgtable_size, 0, pgtable_size);

	/* create pgtable pool for map */
	sdomain->pool = gen_pool_create(vaddr, pgtable_size, PAGE_SHIFT);
	if (!sdomain->pool) {
		tloge("gen_pool create fail\n");
		goto unmap_pgtable;
	}

	/* alloc pgd first */
	sdomain->pgd = (u64 *)(uintptr_t)gen_pool_alloc(sdomain->pool, SZ_4K);
	if (!sdomain->pgd) {
		tloge("PGD alloc fail!!\n");
		goto destory_pool;
	}

	sdomain->pgtable_addr = pgtable_addr;
	sdomain->pgtable_size = pgtable_size;
	sdomain->va_base = vaddr;
	sdomain->pgd_phys = pool_pa((u32)(uintptr_t)sdomain->pgd,
					vaddr, pgtable_addr);
	return sdomain;
destory_pool:
	gen_pool_destory(sdomain->pool);
unmap_pgtable:
	ret = sre_unmap(vaddr, pgtable_size);
	if (ret)
		tloge("unmap pgtabe va_base:0x%x size:0x%x failed",
			vaddr, pgtable_size);
free_domain:
	SRE_MemFree(OS_MID_SYS, sdomain);

	return NULL;
}

void siommu_domain_free(struct smmu_domain *sdomain)
{
	if (!sdomain) {
		tloge("invalid sdomain\n");
		return;
	}

	/* clear pgtable */
	(void)memset_s((void *)(uintptr_t)sdomain->va_base,
			sdomain->pgtable_size, 0, sdomain->pgtable_size);
	v7_dma_flush_range(sdomain->va_base,
			   sdomain->va_base + sdomain->pgtable_size);

	/* destory gen pool */
	gen_pool_destory(sdomain->pool);

	/* unmap pgtable section vaddr */
	if (sre_unmap(sdomain->va_base, sdomain->pgtable_size))
		tloge("unmap pgtabe va_base:0x%x size:0x%x failed",
			sdomain->va_base, sdomain->pgtable_size);

	/* free sdomain */
	SRE_MemFree(OS_MID_SYS, sdomain);
}
