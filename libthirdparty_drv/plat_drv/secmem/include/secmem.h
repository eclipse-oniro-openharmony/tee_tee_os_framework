/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2001-2020. All rights reserved.
 * Description: This program is used for sec mem
 * Author: jianfujian
 * Create: 2001-1-1
 */

#ifndef __SECMEM_H
#define __SECMEM_H

#include "secmem_priv.h"
#include "mem_page_ops.h"
#include <errno.h>

#define SZ_4K 0x1000
#define SZ_8K 0x2000
#define SZ_16K 0x4000
#define SZ_32K 0x8000
#define SZ_48K 0xc000
#define SZ_64K 0x10000
#define SZ_512K 0x80000
#define SZ_1M 0x100000
#define SZ_2M 0x200000
#define SZ_4M 0x400000
#define SZ_8M 0x800000
#define SZ_16M 0x1000000
#define SZ_32M 0x2000000
#define SZ_64M 0x4000000
#define SZ_512M 0x20000000
#define SZ_1G 0x40000000

#define IOMMU_READ	(1 << 0)
#define IOMMU_WRITE	(1 << 1)
#define IOMMU_CACHE	(1 << 2) /* DMA cache coherency */
#define IOMMU_NOEXEC	(1 << 3)
#define IOMMU_DEVICE	(1 << 7)
#define IOMMU_SEC	(1 << 8)
#define IOMMU_EXEC	(1 << 9)

enum ion_ta_tag {
	ION_SEC_CMD_PGATBLE_INIT = 0,
	ION_SEC_CMD_ALLOC,
	ION_SEC_CMD_FREE,
	ION_SEC_CMD_MAP_IOMMU,
	ION_SEC_CMD_UNMAP_IOMMU,
	ION_SEC_CMD_MAP_USER,
	ION_SEC_CMD_UNMAP_USER,
	ION_SEC_CMD_TABLE_SET,
	ION_SEC_CMD_TABLE_CLEAN,
	ION_SEC_CMD_VLTMM,
#ifdef SECMEM_UT
	ION_SEC_CMD_TEST,
#endif
	ION_SEC_CMD_MAX,
};

enum SEC_Task {
	SEC_TASK_DRM = 0x0,
	SEC_TASK_SEC,
	SEC_TASK_TINY,
	SEC_TASK_MAX,
};

struct mem_chunk_list {
	unsigned int protect_id;
	union {
		unsigned int nents;
		unsigned int buff_id;
	};
	unsigned int va;
	void *buffer_addr; /* Must be the start addr of struct tz_pageinfo */
	unsigned int size;
	unsigned int cache;
	int prot;
	int mode;
	unsigned int smmuid;
	unsigned int sid;
	unsigned int ssid;
};
#ifndef CONFIG_PRODUCT_ARMPC
extern int sion_map_iommu(struct mem_chunk_list *mcl);
extern int sion_unmap_iommu(struct mem_chunk_list *mcl);
extern int sion_map_kernel(struct mem_chunk_list *mcl);
extern int sion_unmap_kernel(struct mem_chunk_list *mcl);
extern int sion_map_user(struct mem_chunk_list *mcl);
extern int sion_unmap_user(struct mem_chunk_list *mcl);
extern unsigned int hisi_sion_get_pgtable(unsigned int protect_id);
extern int hisi_sion_check_mem(paddr_t addr, unsigned int size,
				unsigned int protect_id);
extern int siommu_map(struct smmu_domain *sdomain, struct sglist *sglist,
				u32 iova, u32 size, int prot, int mode);
extern int siommu_unmap(struct smmu_domain *sdomain,
				struct sglist *sglist,
				u32 iova, u32 size, int mode);
extern struct smmu_domain *siommu_domain_grab(u32 protect_id);
extern void destory_siommu_domain(struct smmu_domain *sdomain);

extern unsigned int sion_mmap(void *sglist, unsigned int size,
				unsigned int feature_id, int mode,
				int cached, int used_by_ta);
extern int sion_munmap(void *sglist, unsigned int va, unsigned int size,
				unsigned int feature_id,
				int mode, int used_by_ta);

extern int sion_ddr_sec_cfg(u16 buffer_id, unsigned int size,
				int cached, int feature_id, int ddr_cfg_type);
extern unsigned int sion_mmap_sfd(unsigned int sfd, unsigned int size,
				unsigned int feature_id, int mode,
				int cached, int used_by_ta);
extern int sion_munmap_sfd(unsigned int sfd, unsigned int va, unsigned int size,
				unsigned int feature_id, int mode,
				int used_by_ta);
extern struct sglist *sion_get_sglist_from_sfd(unsigned int sfd,
				unsigned int feature_id);
#ifdef SECMEM_UT
extern int test_teeos_sion(struct mem_chunk_list *mcl);
#endif
#else
static inline int sion_map_user()
{
	return 0;
}

static inline int sion_unmap_user()
{
	return 0;
}

static inline unsigned int sion_mmap_sfd()
{
	return 0;
}

static inline int sion_munmap_sfd()
{
	return 0;
}

static inline struct sglist *sion_get_sglist_from_sfd()
{
	return 0;
}
#endif
#endif
