/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: hi_smmu
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#ifndef __HI_SMMU_MEM_H
#define __HI_SMMU_MEM_H

#include "hi_log.h"
#include "hi_tee_drv_mem.h"
#include "hi_type_dev.h"

/*
 * smmu space is started with 0x0, and we need to make a distinction between smmu space
 * in no secure which is startd with 0x400000,  And size is 0xffc00000.
 */
#define HISI_SEC_SMMU_BASE  0x0
#define HISI_SEC_SMMU_SIZE  0xffc00000

/*
 * we need to make a distinction between smmu space in no secure which is
 * startd with 0x400000, 0x80000000 is set to sec_smmu begin
 */
#ifdef CFG_HISI_LOWRAM
#define HISI_SEC_SMMU_SPACE_BASE    0x400000
#define HISI_SEC_SMMU_SPACE_SIZE    0x3fb00000
#define HISI_RESERGVED_SEC_SMMU_SPACE_SIZE HISI_SEC_SMMU_SPACE_BASE
#else
#define HISI_SEC_SMMU_SPACE_BASE    0x400000
#define HISI_SEC_SMMU_SPACE_SIZE    0xf0000000
#define HISI_RESERGVED_SEC_SMMU_SPACE_SIZE HISI_SEC_SMMU_SPACE_BASE
#endif

#define SMMU_ERR_RW_SIZE        0x100

/* smmu pagetable need to put into 2G smmu address range, 1 level pagetable need
 * about 0x200000 mem to store
 **/
#define SMMU_PAGETBL_SIZE       0x200000

#define HISI_PA_SHIFT   4
#define HISI_TAG_MASK   0xFC
#define HISI_TAG_SHIFT 2
#define HISI_IOMMU_PE_V_MASK (1 << 0)

/* the size of share mem to support in secure ram  */
#define SHARE_MEM_START     0x10000000
#define MAX_SHARE_MEM       0xf0000000

struct hi_tz_pageinfo {
    unsigned long long phys_addr;
    unsigned int npages;
};

struct hisi_smmu_domain {
        unsigned long long iova_start;
        unsigned long long iova_size;
        unsigned long *bitmap;
        unsigned long long bitmap_pfn_base;
        unsigned long long bitmap_pfn_count;
};

struct sec_smmu {
        unsigned long long pgtbl_pbase;
        unsigned long long pgtbl_size;
        unsigned long long r_err_base;
        unsigned long long w_err_base;
};

struct hisi_smmu {
        void *pgtbl_addr;
        unsigned long long pgtbl_size;
        struct hisi_smmu_domain *hisi_domain;
        struct sec_smmu *sec_smmu;
};

#ifndef HI_SUCCESS
#define HI_SUCCESS      0
#endif
#ifndef HI_FAILED
#define HI_FAILED       (-1)
#endif

#define INVIDE_ADDR     0

#define SZ_4K                           0x00001000
#define IS_ALIGNED(x, a)                (((x) & ((typeof(x))(a) - 1)) == 0)

/* Round up the even multiple of size, size has to be a multiple of 2 */
#define ROUNDUP(v, size) (((v) + ((size) - 1)) & ~((size) - 1))

/* Round down the even multiple of size, size has to be a multiple of 2 */
#define ROUNDDOWN(v, size) ((v) & ~((size) - 1))

#ifndef ALIGN
#define ALIGN   ROUNDUP
#endif

#ifndef HI_TEE_LOG_SUPPORT
#define SMMU_RELEASE_SUPPORT
#else
#undef SMMU_RELEASE_SUPPORT
#endif

#define pr_info(fmt...)          tlogi(fmt)
#define pr_err(fmt...)           tloge(fmt)
#define pr_warn(fmt...)          tlogw(fmt)
#define pr_debug(fmt...)         tlogd(fmt)

#define SECMEMAREA      1
#define NONSECMEM       0

static inline int smmu_access_check(void *addr, size_t size)
{
    return HI_SUCCESS;
}

static inline int smmu_access_read_right_check(void *addr, size_t size)
{
    return HI_SUCCESS;
}

static inline int smmu_access_write_right_check(void *addr, size_t size)
{
    return HI_SUCCESS;
}

#define PAGESIZE_4K

#if defined(PAGESIZE_4K)
#define HISI_IOMMU_PE_PA_MASK 0xFFFFFF00
#define HISI_SMMU_BLOCK_SIZE 0x1000
#define HISI_PAGE_SHIFT 12
#define HISI_PAGE_SIZE  0x1000
#elif defined(PAGESIZE_16K)
#define HISI_SMMU_BLOCK_SIZE 0x4000
#define HISI_IOMMU_PE_PA_MASK 0xFFFFFC00
#define HISI_PAGE_SHIFT 14
#define HISI_PAGE_SIZE  0x4000
#elif defined(PAGESIZE_64K)
#define HISI_SMMU_BLOCK_SIZE 0x10000
#define HISI_IOMMU_PE_PA_MASK 0xFFFFF000
#define HISI_PAGE_SHIFT 16
#define HISI_PAGE_SIZE  0x10000
#endif

extern struct hisi_smmu *g_hisi_smmu_p;
extern void v7_dma_flush_range(unsigned long start, unsigned long end);
extern void v7_flush_kern_cache_all(void);

unsigned long long _hisi_alloc_smmu_range(unsigned long long size);

int _hisi_free_smmu_range(unsigned long long smmu_addr, unsigned long long size);

/*
 * func: map to sec-smmu
 * pageinfoaddr: input, the virt addr of mem info buffer
 * total_size: input, the total size of the mem
 * nblocks: input, the number of mem blocks
 * tag: input, secure tag
 * return: smmu address if exec success
 *         0 if exec failed
 */
unsigned long long hisi_map_smmu(void *pageinfoaddr, unsigned long long total_size,
                                 unsigned int nblocks, unsigned int tag, unsigned long long smmu);

/*
 * func: map to sec-smmu
 * phys_addr: input, the phys_addr of mem  buffer
 * total_size: input, the total size of the mem
 * tag: input, secsmmu tag
 * return: smmu address if exec success
 *         0 if exec failed
 */
unsigned long long hisi_map_smmu_by_phys(unsigned long long phys_addr, unsigned long long total_size, unsigned int tag);

/*
 * func: unmap from sec-smmu
 * smmu_addr: input, the sec_smmu of mem info buffer
 * total_size: input, the total size of the mem
 * return: 0 if exec success
 *         -1 if exec failed
 */
int hisi_unamp_smmu(unsigned long long smmu_addr, unsigned long long total_size);

/*
 * func: map to sec-cpu in kernel
 * pageinfoaddr: input, the virt addr of mem info buffer
 * nblocks: input, the number of sg
 * total_size: input, the total size of the mem
 * sec_type: input, indicate if the mem is secure, 0:secure  1:no-secure
 * cached: input, indicate the cache attr when create page table
 * return: sec-cpu virt address if exec success
 *         NULL if exec failed
 */
void *hisi_map_cpu(void *pageinfoaddr, unsigned int nblocks,
                   unsigned long long total_size,
                   bool sec_type, bool cached);
/*
 * func: unmap from sec-cpu in kernel
 * va_addr: input, the sec cpu virt addr of mem buffer
 * size: input, the total size of the mem
 * sec_type: input, the va_addr is secure or not, because often secure has
 *      different mapping from the nonsecure
 * return:   NULL
 */
void hisi_unmap_cpu(const void *va_addr, unsigned long long size, bool sec_type);

/*
 * func: map to sec-cpu in ta
 * pageinfoaddr: input, the virt addr of mem info buffer
 * nblocks: input, the number of sg
 * total_size: input, the total size of the mem
 * sec_type: input, indicate if the mem is secure, 0:secure  1:no-secure
 * cached: input, indicate the cache attr when create page table
 * return: sec-cpu virt address if exec success
 *         NULL if exec failed
 */
void *hisi_ta_map_cpu(void *pageinfoaddr, unsigned int nblocks,
                      unsigned long long total_size,
                      bool sec_type, bool cached);

/*
 * func: unmap from sec-cpu in ta
 * va_addr: input, the sec cpu virt addr of mem buffer
 * size: input, the total size of the mem
 * sec_type: input, the va_addr is secure or not, because often secure has
 *      different mapping from the nonsecure
 * return:   NULL
 */
void hisi_ta_unmap_cpu(const void *va_addr, unsigned long long size, bool sec_type);

/*
 * func: flush the cache
 * virt: input, the virt addr of the mem
 * size: input, the size of mem
 * return: NULL
 */
void smmu_flush_cache_area(void *virt, unsigned long long size);

/*
 * func: check the mem if it is secure
 * phys: input, the phys addr of mem
 * size: input, the size of mem
 * return:      1, means secure mem
 *              0, means no secure mem
 */
int sec_mem_check(unsigned long long phys, unsigned long long size);

/*
 * func: clear secure mem bitmap
 * pageinfoaddr: input, the virt addr of meminfo
 * total_size: input, the whole size of mem to clear bitmap
 * return:
 *              0, exec successfully
 *              -1, exec failed
 */
int clear_sec_mem_bitmap(void *pageinfoaddr, unsigned long long total_size);

/*
 * func: set secure mem bitmap
 * pageinfoaddr: input, the virt addr of  meminfo
 * total_size: input, the whole size of mem to set bitmap
 * return:
 *              0, exec successfully
 *              -1, exec failed
 */
int set_sec_mem_bitmap(void *pageinfoaddr, unsigned long long total_size);

int hisi_update_pagetable(unsigned long long smmu_addr, unsigned long long size, unsigned int tag);
/*
 * func: check the mem if in zone_type mem area
 * phys_addr: input, the phys_addr of mem will to check
 * size: the size of of mem
 * zone_type: the type of mem area

 * return:
 *        0, exec successfully
 *        -1, exec failed
 */
int phy_area_available_check(unsigned long long phys_addr, unsigned long long size, unsigned int zone_type);
#endif
