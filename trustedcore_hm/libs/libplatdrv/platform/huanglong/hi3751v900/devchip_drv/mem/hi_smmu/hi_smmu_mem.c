/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: hi_smmu
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#include "hi_smmu_mem.h"
#include "bitmap.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_mem_layout.h"

struct hisi_smmu *g_hisi_smmu_p = NULL;

int phy_area_available_check(unsigned long long phys_addr, unsigned long long size, unsigned int zone_type)
{
    unsigned long long ddr_start;
    unsigned long long ddr_size;
    unsigned long long ddr_end;
    long long phys_end;

    /* check if the mem is in ddr */
    ddr_start = (unsigned long long)hi_tee_drv_mem_get_zone_range(zone_type, (unsigned long long *)&ddr_size);
    if (ddr_size == 0) {
        pr_err("cannot find ddr size\n");
        return HI_FAILED;
    }

    ddr_end = ddr_start + ddr_size;
    phys_end = (long long)phys_addr + (long long)size;
    if ((ddr_start <= phys_addr) && ((long long)phys_addr <= phys_end) && (phys_end <= (long long)ddr_end)) {
        return HI_SUCCESS;
    }

    return HI_FAILED;
}

int smmu_area_available_check(unsigned long long smmu_addr, unsigned long long size, unsigned long long align_size)
{
    unsigned long addr_start;
    long long addr_end;

    if ((smmu_addr == 0) || (size == 0) || (align_size == 0) || (size > HISI_SEC_SMMU_SPACE_SIZE)) {
        pr_err("err args\n");
        return HI_FAILED;
    }

    if ((smmu_addr + size) < smmu_addr) { /* avoid overflow */
        pr_err("err args\n");
        return HI_FAILED;
    }

    addr_start = smmu_addr;
    addr_end  = (long long)smmu_addr + (long long)size;

    if (!IS_ALIGNED(smmu_addr, align_size) || !IS_ALIGNED(size, align_size)) {
        pr_err("param input may be not aligned to 0x%llx!\n", align_size);
        return HI_FAILED;
    }

    if ((addr_start >= HISI_SEC_SMMU_SPACE_BASE) && (addr_start <= addr_end) &&
        (addr_end <= (long long)(HISI_SEC_SMMU_SPACE_BASE + HISI_SEC_SMMU_SPACE_SIZE))) {
        return HI_SUCCESS;
    }

    return HI_FAILED;
}

unsigned long long _hisi_alloc_smmu_range(unsigned long long size)
{
    struct hisi_smmu *hisi_smmu = g_hisi_smmu_p;
    unsigned long long start = 0;
    unsigned long long mask = 0;
    unsigned long long bitmap_no;
    unsigned long long bitmap_cnt;
    unsigned long long smmu_start;
    struct hisi_smmu_domain *smmu_domain = NULL;

    if (!size || (hisi_smmu == NULL) || (hisi_smmu->hisi_domain == NULL)) {
        pr_err("err args\n");
        goto err;
    }

    if (!size) {
        pr_err("err args,size:0x%llx\n", size);
        goto err;
    }

    smmu_domain = hisi_smmu->hisi_domain;

    size = ALIGN(size, HISI_PAGE_SIZE);
    bitmap_cnt = size >> HISI_PAGE_SHIFT;
    bitmap_no = bitmap_find_next_zero_area(smmu_domain->bitmap, smmu_domain->bitmap_pfn_count, start, bitmap_cnt, mask);
//    pr_err("kkzzzkk : smmu_domain->bitmap_pfn_count:0x%llx  start:0x%llx  bitmap_cnt:0x%llx  mask:0x%llx\n",  smmu_domain->bitmap_pfn_count, start, bitmap_cnt, mask);
    if (bitmap_no >= smmu_domain->bitmap_pfn_count) {
		pr_err("kkzzzkk : smmu_domain->bitmap_pfn_count:0x%llx  start:0x%llx  bitmap_cnt:0x%llx  mask:0x%llx\n",  smmu_domain->bitmap_pfn_count, start, bitmap_cnt, mask);
        pr_err("no smmu space left, alloc:0x%llx  bitmmap_no:0x%llx \n", bitmap_cnt, bitmap_no);
        goto err;
    }

    bitmap_set(smmu_domain->bitmap, bitmap_no, bitmap_cnt);
    smmu_start = smmu_domain->bitmap_pfn_base + bitmap_no;
    smmu_start = smmu_start << HISI_PAGE_SHIFT;

    return smmu_start;
err:
    return INVIDE_ADDR;
}

int _hisi_free_smmu_range(unsigned long long smmu_addr, unsigned long long size)
{
    unsigned long long bitmap_no;
    unsigned long long bitmap_cnt;
    struct hisi_smmu *hisi_smmu = g_hisi_smmu_p;
    struct hisi_smmu_domain *smmu_domain = NULL;
    int ret;

    ret = smmu_area_available_check(smmu_addr, size, SZ_4K);
    if (ret != HI_SUCCESS) {
        pr_err("err args\n");
        return HI_FAILED;
    }

    if (hisi_smmu == NULL || hisi_smmu->hisi_domain == NULL) {
        pr_err("hisi_smmu is error\n");
        return HI_FAILED;
    }

    smmu_domain = hisi_smmu->hisi_domain;
    bitmap_no = (smmu_addr >> HISI_PAGE_SHIFT) - smmu_domain->bitmap_pfn_base;
    bitmap_cnt = (ALIGN(size, HISI_PAGE_SIZE)) >> HISI_PAGE_SHIFT;
    if ((bitmap_no + bitmap_cnt) > (smmu_domain->bitmap_pfn_base + smmu_domain->bitmap_pfn_count)) {
        pr_err("err args\n");
        goto err;
    }

    bitmap_clear(smmu_domain->bitmap, bitmap_no, bitmap_cnt);

    return HI_SUCCESS;
err:
    return HI_FAILED;
}

/*
 * Check the mem which to be mapped smmu is available.
 * The mem should only be in share mem or sec mmz.
 * return 0 means the mem is available.
 * others means the mem check failed or is not available.
 */
static int is_smmu_phy_available(unsigned long long phys_addr, unsigned long long size)
{
    int ret;

    /* check if the mem is in ddr */
    ret = phy_area_available_check(phys_addr, size, TOTAL_MEM_RANGE);
    if (ret != HI_SUCCESS) {
        return HI_FAILED;
    }
    ret = phy_area_available_check(phys_addr, size, SEC_MMZ_MEM);
    if (ret == HI_SUCCESS) {
        return HI_SUCCESS;
    }
#ifdef CFG_HI_TEE_SMMZ2_SUPPORT
    ret = phy_area_available_check(phys_addr, size, SEC_MMZ2_MEM);
    if (ret == HI_SUCCESS) {
        return HI_SUCCESS;
    }
#endif
    ret = phy_area_available_check(phys_addr, size, SEC_MEM_RANGE);
    if (ret == HI_SUCCESS) {
        return HI_FAILED;
    }

    return HI_SUCCESS;
}


/*
 * smmu_addr,phys_addr,size must be aligned with 4K, and the caller outside
 * shoud be guaranteed.
 */
static int _hisi_map_smmu(unsigned long long smmu_addr, unsigned long long phys_addr,
                          unsigned long long size, unsigned int tag)
{
    struct hisi_smmu *hisi_smmu = g_hisi_smmu_p;
    struct hisi_smmu_domain *smmu_domain = NULL;
    unsigned long long t_size = 0;
    unsigned long long offset;
    unsigned int *pgtbl = NULL;
    int ret;

    ret = smmu_area_available_check(smmu_addr, size, SZ_4K);
    if (ret != HI_SUCCESS) {
        pr_err("err args\n");
        return HI_FAILED;
    }

    /* check the mem which to map smmu if it's legal */
    if (is_smmu_phy_available(phys_addr, size)) {
        pr_err("The mem is rejective to map smmu!\n");
        return HI_FAILED;
    }

    if (hisi_smmu == NULL) {
        pr_err(" hisi_smmu_p is null!\n");
        return HI_FAILED;
    }

    smmu_domain = hisi_smmu->hisi_domain;

    if ((hisi_smmu->pgtbl_addr) == NULL) {
        pr_err("pgtbal is null!\n");
        return HI_FAILED;
    }

    /* set validate pagetable entry    */
    for (; t_size < size;) {
        pgtbl = (unsigned int *)hisi_smmu->pgtbl_addr;

        /* get the offset of first page entry */
        offset = (smmu_addr - smmu_domain->iova_start) >> HISI_PAGE_SHIFT;

        pgtbl = pgtbl + offset;

        /* fill in pagetable entry    */
        *pgtbl = ((phys_addr >> HISI_PA_SHIFT) &
                HISI_IOMMU_PE_PA_MASK) | HISI_IOMMU_PE_V_MASK |
                ((tag<<HISI_TAG_SHIFT) & HISI_TAG_MASK);

        smmu_addr = smmu_addr + HISI_SMMU_BLOCK_SIZE;
        phys_addr = phys_addr + HISI_SMMU_BLOCK_SIZE;
        t_size = t_size + HISI_SMMU_BLOCK_SIZE;
    }

    return HI_SUCCESS;
}

/* set invalidate pagetable entry   */
static int _hisi_map_smmu_invalidate(unsigned long long smmu_addr,
    unsigned long long size)
{
    struct hisi_smmu *hisi_smmu = g_hisi_smmu_p;
    struct hisi_smmu_domain *smmu_domain = NULL;
    unsigned long long offset;
    unsigned int *pgtbl = NULL;
    long long tmp;

    if (!smmu_addr || !size || (hisi_smmu == NULL) ||
        (smmu_addr < HISI_SEC_SMMU_SPACE_BASE) ||
        (size > HISI_SEC_SMMU_SPACE_SIZE) ||
            (hisi_smmu->hisi_domain == NULL)) {
        pr_err("err args\n");
        goto err;
    }

    if (!IS_ALIGNED(smmu_addr, HISI_SMMU_BLOCK_SIZE) ||
        !IS_ALIGNED(size, HISI_SMMU_BLOCK_SIZE)) {
        pr_err("param input may be not aligned to pagesize!\n");
        goto err;
    }

    tmp = (long long)smmu_addr;
    tmp = tmp + (long long)size;
    if ((tmp >= (long long)(HISI_SEC_SMMU_SPACE_BASE +
        HISI_SEC_SMMU_SPACE_SIZE)) || ((smmu_addr + size) < smmu_addr)) {
        pr_err("err args(overflow):smmu:0x%llx  size:0x%llx !\n",
               smmu_addr, size);
        goto err;
    }

    smmu_domain = hisi_smmu->hisi_domain;

    if (!hisi_smmu->pgtbl_addr) {
        pr_err("pgtbal is null!\n");
        goto err;
    }

    /* //if phys_addr is 0, the pagetable entry is invalidate
     * only the last 4k smmu space in the range, the pagetable
     * entry is set to be invalidate.
     **/
    pgtbl = (unsigned int *)hisi_smmu->pgtbl_addr;

    /* get the offset of first page entry */
    offset = (smmu_addr - smmu_domain->iova_start) >> HISI_PAGE_SHIFT;
    pgtbl = pgtbl + offset;

    /* fill in pagetable entry    */
    *pgtbl = HISI_IOMMU_PE_PA_MASK;

    return HI_SUCCESS;
err:
    return HI_FAILED;
}


static int _hisi_unmap_smmu(unsigned long long smmu_addr, unsigned long long size)
{
    struct hisi_smmu *hisi_smmu = g_hisi_smmu_p;
    struct hisi_smmu_domain *smmu_domain = NULL;
    unsigned long long t_size = 0;
    unsigned long long offset;
    unsigned int *pgtbl = NULL;
    long long tmp;

    if (!smmu_addr || !size || (hisi_smmu == NULL) ||
        (smmu_addr < HISI_SEC_SMMU_SPACE_BASE) ||
        (size > HISI_SEC_SMMU_SPACE_SIZE) ||
                (hisi_smmu->hisi_domain == NULL)) {
        pr_err("err args\n");
        goto err;
    }

    if (!IS_ALIGNED(smmu_addr, HISI_SMMU_BLOCK_SIZE) ||
        !IS_ALIGNED(size, HISI_SMMU_BLOCK_SIZE)) {
        pr_err("param input may be not aligned to 4K!\n");
        goto err;
    }

    tmp = (long long)smmu_addr;
    tmp = tmp + (long long)size;
    if ((tmp >= (long long)(HISI_SEC_SMMU_SPACE_BASE +
        HISI_SEC_SMMU_SPACE_SIZE)) || ((smmu_addr + size) < smmu_addr)) {
        pr_err("err args(overflow):smmu:0x%llx  size:0x%llx !\n",
               smmu_addr, size);
        goto err;
    }

    smmu_domain = hisi_smmu->hisi_domain;

    if (!hisi_smmu->pgtbl_addr) {
        pr_err("pgtbal is null!\n");
        goto err;
    }

    for (; t_size < size;) {
        pgtbl = (unsigned int *)hisi_smmu->pgtbl_addr;

        /* get the offset of first page entry */
        offset = (smmu_addr - smmu_domain->iova_start) >> 12; // shift right 12 bit
        pgtbl = pgtbl + offset;

        /* clear pagetable entry    */
        *pgtbl = 0;

        smmu_addr = smmu_addr + HISI_SMMU_BLOCK_SIZE;
        t_size = t_size + HISI_SMMU_BLOCK_SIZE;
    }

    return HI_SUCCESS;
err:
    return HI_FAILED;
}

int hisi_update_pagetable(unsigned long long smmu_addr, unsigned long long size, unsigned int tag)
{
    struct hisi_smmu *hisi_smmu = g_hisi_smmu_p;
    struct hisi_smmu_domain *smmu_domain = NULL;
    unsigned long long t_size = 0;
    unsigned long long offset;
    unsigned int *pgtbl = NULL;
    long long tmp;
    unsigned int entry;

    if (!smmu_addr || !size || (smmu_addr < HISI_SEC_SMMU_SPACE_BASE) || (size > HISI_SEC_SMMU_SPACE_SIZE)) {
        pr_err("param input must be not 0, smmu:0x%llx \
            size:0x%llx !\n", smmu_addr, size);
        goto err;
    }
    if (hisi_smmu == NULL) {
        pr_err(" hisi_smmu_p is null!\n");
        goto err;
    }

    if (!IS_ALIGNED(smmu_addr, HISI_SMMU_BLOCK_SIZE) ||
        !IS_ALIGNED(size, HISI_SMMU_BLOCK_SIZE)) {
        pr_err("param input may be not aligned to pagesize!\n");
        goto err;
    }

    tmp = (long long)smmu_addr + (long long)size;
    if ((tmp >= (long long)(HISI_SEC_SMMU_SPACE_BASE +
        HISI_SEC_SMMU_SPACE_SIZE)) || ((smmu_addr + size) < smmu_addr)) {
        pr_err("err args(overflow):smmu:0x%llx  size:0x%llx !\n",
               smmu_addr, size);
        goto err;
    }

    smmu_domain = hisi_smmu->hisi_domain;

    if (!hisi_smmu->pgtbl_addr) {
        pr_err("pgtbal is null!\n");
        goto err;
    }

    /* set validate pagetable entry    */
    for (; t_size < size;) {
        pgtbl = (unsigned int *)hisi_smmu->pgtbl_addr;

        /* get the offset of first page entry */
        offset = (smmu_addr - smmu_domain->iova_start) >> HISI_PAGE_SHIFT;

        pgtbl = pgtbl + offset;
        entry = *pgtbl;
        /* update pagetable entry    */
        *pgtbl = (entry & (~HISI_TAG_MASK)) | ((tag<<HISI_TAG_SHIFT) & HISI_TAG_MASK);

        smmu_addr = smmu_addr + HISI_SMMU_BLOCK_SIZE;
        t_size = t_size + HISI_SMMU_BLOCK_SIZE;
    }

    return HI_SUCCESS;
err:
    return HI_FAILED;
}

static unsigned long long hisi_map_smmu_getsmmustart(unsigned long long total_size,
                                                     unsigned long long smmu, unsigned long long *size_align)
{
    unsigned long long smmu_start;
    unsigned long long size = ALIGN(total_size, HISI_SMMU_BLOCK_SIZE);
    /*
     * one more 4K smmu space is needed, and the last 4K smmu space
     * will create invalidate pagetable entry. So it will make sure
     * that logic device can not access cross the border.
     */
    size = size + HISI_SMMU_BLOCK_SIZE;
    *size_align = size;

    if (!smmu) {
        smmu_start = _hisi_alloc_smmu_range(size);
        if (smmu_start == INVIDE_ADDR) {
            pr_err("%s(%d) get failed smmu_start \n", __FUNCTION__, __LINE__);
            return INVIDE_ADDR;
        }
    } else {
        smmu_start = smmu;
    }

    return smmu_start;
}

/*
 * pageinfoaddr: the virt addr of first memblock
 * total_size: the total size of whole mem
 * noblocks: the number of mem blocks
 */
unsigned long long hisi_map_smmu(void *pageinfoaddr, unsigned long long total_size,
                                 unsigned int nblocks, unsigned int tag, unsigned long long smmu)
{
    unsigned long long size, smmu_start, smmu_addr;
    unsigned long long map_size = 0;
    int ret, i;
    struct hi_tz_pageinfo *pginfo = NULL;

    if (pageinfoaddr == NULL || !total_size) {
        pr_err("err args. pageinfoaddr:0x%x size:0x%llx\n", pageinfoaddr, total_size);
        return INVIDE_ADDR;
    }

    smmu_addr = smmu_start = hisi_map_smmu_getsmmustart(total_size, smmu, &size);
    if (smmu_start == INVIDE_ADDR) {
        return INVIDE_ADDR;
    }

    pginfo = (struct hi_tz_pageinfo *)pageinfoaddr;
    for (i = 0; i < nblocks; i++) {
        if (pginfo == NULL) {
            pr_err("Maybe overflow\n");
            goto out;
        }
        /* create pagetable entry  */
        ret = _hisi_map_smmu(smmu_addr, pginfo->phys_addr, pginfo->npages << HISI_PAGE_SHIFT, tag);
        if (ret == HI_FAILED) {
            pr_err(" map smmu failed! smmu_start:0x%llx smmu_addr:0x%llx\n", smmu_start, smmu_addr);
            goto out;
        }

        map_size = map_size + (pginfo->npages << HISI_PAGE_SHIFT);
        smmu_addr = smmu_addr + (pginfo->npages << HISI_PAGE_SHIFT);
        pginfo++;

        /* set last 4k smmu space invalidate pagetable entry   */
        if (map_size == total_size) {
            if (_hisi_map_smmu_invalidate(smmu_addr, HISI_SMMU_BLOCK_SIZE) == HI_FAILED) {
                pr_err("set smmu invalidate failed!\n");
                goto out;
            }
            break;
        }
    }
    if (map_size != total_size) {
        pr_err("map smmu failed!\n");
        goto out;
    }

    return smmu_start;
out:
    if (map_size) {
        (void)_hisi_unmap_smmu(smmu_start, map_size);
    }
    if (_hisi_free_smmu_range(smmu_start, size) == HI_FAILED) {
        pr_err("%s(%d) \n", __FUNCTION__, __LINE__);
    }
    return INVIDE_ADDR;
}

/*
 * phys_addr: the phys_addr of mem
 * total_size: the total size of whole mem
 */
unsigned long long hisi_map_smmu_by_phys(unsigned long long phys_addr, unsigned long long total_size, unsigned int tag)
{
    unsigned long long size;
    unsigned long long smmu_start;
    unsigned long long smmu_addr;
    int ret;

    if (!phys_addr || !total_size) {
        pr_err("err args. phys_addr:0x%llx total_size:0x%llx\n", phys_addr, total_size);
        goto err;
    }

    total_size = ALIGN(total_size, HISI_SMMU_BLOCK_SIZE);
    /*
     * one more 4K smmu space is needed, and the last 4K smmu space
     * will create invalidate pagetable entry. So it will make sure
     * that logic device can not access cross the border.
     */
    size = total_size + HISI_SMMU_BLOCK_SIZE;

    smmu_start = _hisi_alloc_smmu_range(size);
    if (smmu_start == INVIDE_ADDR) {
        pr_err("_hisi_alloc_smmu_range failed!\n");
        goto err;
    }

    smmu_addr = smmu_start;
    ret = _hisi_map_smmu(smmu_addr, phys_addr, total_size, tag);
    if (ret == HI_FAILED) {
        pr_err("map smmu failed! smmu_start:0x%x \
                smmu_addr:0x%x\n", smmu_start, smmu_addr);
        goto exit;
    }

    ret = _hisi_map_smmu_invalidate((smmu_addr + total_size), HISI_SMMU_BLOCK_SIZE);
    if (ret == HI_FAILED) {
        pr_err("set smmu invalidate failed!\n");
        goto out;
    }

    return smmu_start;
out:
    if (_hisi_unmap_smmu(smmu_start, total_size) == HI_FAILED) {
        pr_err("%s(%d) \n", __FUNCTION__, __LINE__);
    }
exit:
    if (_hisi_free_smmu_range(smmu_start, total_size) == HI_FAILED) {
        pr_err("%s(%d) \n", __FUNCTION__, __LINE__);
    }
err:
    return INVIDE_ADDR;
}

int hisi_unamp_smmu(unsigned long long smmu_addr, unsigned long long total_size)
{
    int ret;
    unsigned long long size;

    if (!smmu_addr || !total_size) {
        pr_err("err args: smmu:0x%llx size:0x%llx\n", smmu_addr, total_size);
        return HI_FAILED;
    }

    size = total_size + HISI_SMMU_BLOCK_SIZE;

    ret = _hisi_unmap_smmu(smmu_addr, size);
    if (ret == HI_FAILED) {
        pr_err("_hisi_unmap_smmu failed! smmu:0x%x \
            size:0x%x \n", smmu_addr, size);
        return HI_FAILED;
    }

    ret = _hisi_free_smmu_range(smmu_addr, size);
    if (ret == HI_FAILED) {
        pr_err("_hisi_free_smmu_range failed! smmu:0x%x \
            size:0x%x \n", smmu_addr, size);
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

void *hisi_map_cpu(void *pageinfoaddr, unsigned int nblocks, unsigned long long total_size, bool sec_type, bool cached)
{
    struct hi_tee_hal_sg_info sg;
    unsigned int va_addr;
    int ret;

    if (pageinfoaddr == NULL || total_size == 0) {
        pr_err("err args  pageinfoaddr:0x%x total_size:0x%llx\n", pageinfoaddr, total_size);
        return NULL;
    }

    ret = memset_s(&sg, sizeof(struct hi_tee_hal_sg_info), 0, sizeof(struct hi_tee_hal_sg_info));
    if (ret != EOK) {
        pr_err("memset_s failed\n");
        return NULL;
    }
    sg.pageinfoaddr = pageinfoaddr;
    sg.nblocks      = nblocks;
    sg.size         = (size_t)total_size;
    ret = hi_tee_drv_hal_map_sg(&sg, !!sec_type, !!cached, false, &va_addr);
    if (ret) {
        pr_err("smmu addr map to cpu failed! ret:%d\n", ret);
        goto err;
    }

    return (void *)(uintptr_t)va_addr;

err:
    return NULL;
}

void hisi_unmap_cpu(const void *va_addr, unsigned long long size, bool sec_type)
{
    hi_tee_drv_hal_unmap_sg(va_addr, (unsigned int)size, !!sec_type, false);
}

void smmu_flush_cached(void)
{
    hi_tee_drv_hal_dcache_flush_all();
}

#define CACHEL2 (512*1024)
void smmu_flush_cache_area(void *virt, unsigned long long size)
{
    if ((virt == NULL) || (size == 0)) {
        pr_err("%s err args: virt:0x%x size:0x%llx\n", __func__, (uintptr_t)virt, size);
        return;
    }

    if (size > CACHEL2) {
        hi_tee_drv_hal_dcache_flush_all();
    } else {
        hi_tee_drv_hal_dcache_flush(virt, (size_t)size);
    }
}

int sec_mem_check(unsigned long long phys, unsigned long long size)
{
    int ret;
    /* check if the mem is in ddr */
    ret = phy_area_available_check(phys, size, TOTAL_MEM_RANGE);
    if (ret != HI_SUCCESS) {
        return HI_FAILED;
    }

    /* check if the mem is in ddr */
    ret = phy_area_available_check(phys, size, SEC_MEM_RANGE);
    if (ret == HI_SUCCESS) {
        return SECMEMAREA;
    } else {
        return NONSECMEM;
    }
}
