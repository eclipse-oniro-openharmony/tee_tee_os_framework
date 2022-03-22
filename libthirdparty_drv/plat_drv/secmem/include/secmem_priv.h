#ifndef __SECMEM_PRIV_H
#define __SECMEM_PRIV_H

#include "global_ddr_map.h"
#include "mem_page_ops.h"
#include "sre_typedef.h"
#include "tzmp2_ops.h"

#define IOVA_POOL_SZ 0x3e000000u

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_MIAMICW)
#define DRM_PGTABLE_BASE (HISI_RESERVED_DRM_PGTABLE_BASE)
#define DRM_PGTABLE_SIZE (HISI_RESERVED_DRM_PGTABLE_SIZE)
#else
#define DRM_PGTABLE_BASE 0xFFFFFFFF
#define DRM_PGTABLE_SIZE 0xFFFFFFFF
#endif

struct bitmap {
	u32 bits;
	u32 order;
	u32 *map;
};

struct gen_pool {
	u32 base;
	u32 min_alloc_order;
	struct bitmap sbitmap;
};

struct smmu_domain {
	u32 pgtable_addr;
	u32 pgtable_size;
	u32 pgd_phys;
	u32 pmd_phys;
	u32 pte_phys;
	u64 *pgd;
	u64 *pmd;
	u64 *pte;
	struct gen_pool *pool;
	u32 va_base;
};

extern s32 bitmap_create(struct bitmap *sbitmap, u32 size, u32 order);
extern void bitmap_destroy(struct bitmap *scharmap);
extern s32 bitmap_find_next_zero_area(struct bitmap *sbitmap, u32 size);
extern void bitmap_set_ll(struct bitmap *sbitmap, u32 start_ibits, u32 size);
extern void bitmap_clear_ll(struct bitmap *sbitmap, u32 start_ibits, u32 size);
extern u32 bitmap_count_ll(struct bitmap *sbitmap);

extern struct gen_pool *gen_pool_create(u32 base,
				u32 size, u32 min_alloc_order);
extern void gen_pool_destory(struct gen_pool *pool);
extern u32 gen_pool_alloc(struct gen_pool *pool, u32 size);
extern void gen_pool_free(struct gen_pool *pool, u32 addr, u32 size);
extern u32 gen_pool_size(struct gen_pool *pool);
extern u32 gen_pool_avail(struct gen_pool *pool);

extern void hisi_dump_pgtable(const struct smmu_domain *sdomain,
				u32 iova, u32 size);
extern s32 hisi_smmu_destory_map(const struct smmu_domain *sdomain,
				u32 iova, u32 size);
extern struct smmu_domain *hisi_siommu_init(u32 pgtable_addr, u32 pgtable_size);
extern s32 hisi_smmu_create_map(const struct smmu_domain *sdomain,
				u64 paddr, u32 iova, u32 size, u32 prot);
extern int smmu_handle_mapping(const struct smmu_domain *sdomain,
				u64 va, u64 pa, u64 sz, int prot);
extern u32 smmu_handle_unmapping(const struct smmu_domain *sdomain,
				u64 iova, u64 size);
extern struct smmu_domain *siommu_domain_alloc(u32 pgtable_addr,
				u32 pgtable_size);
extern void siommu_domain_free(struct smmu_domain *sdomain);
#ifdef SECMEM_UT
extern void sion_show_pte(u32 protect_id, u32 iova, u32 size);
#endif
int sion_allocate_phyaddr(u32 size, u64 *addr);

#endif
