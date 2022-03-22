/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: hi_smmu
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#include "hi_smmu_test.h"
#include "hi_tee_drv_mem.h"
#include "hi_smmu_mem.h"

#define REPEAT_CNT  2


static int sec_mmz_alloc_free(const char *name, unsigned long size, hi_tee_mmz_type memtype, int mapsmmu)
{
    int ret;
    hi_tee_mmz_buf p_sec_mmz_buf = {0};
    hi_tee_smmu_buf p_sec_smmu_buf = {0};

    ret = hi_tee_drv_mmz_alloc(name, size, memtype, &p_sec_mmz_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_MMZ_Alloc failed!\n");
        return HI_FAILED;
    }

    if (mapsmmu) {
        ret = hi_tee_drv_mmz_map_secsmmu(&p_sec_mmz_buf, &p_sec_smmu_buf);
        if (ret != HI_SUCCESS) {
            pr_err("drv_tee_mmz_mapToSmmu failed!\n");
            goto out;
        }

        ret = hi_tee_drv_mmz_unmap_secsmmu(&p_sec_smmu_buf, p_sec_mmz_buf.phys_addr);
        if (ret != HI_SUCCESS) {
            pr_err("DRV_TEE_MMZ_UmapFromSmmu failed!\n");
            return HI_FAILED;
        }
    }
out:
    ret = hi_tee_drv_mmz_free(&p_sec_mmz_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_MMZ_Free failed!\n");
        return HI_FAILED;
    }

    return ret;
}


static int sec_mmz_map_unmap(const char *name, unsigned long size, hi_tee_mmz_type memtype, int cached)
{
    int ret;
    hi_tee_mmz_buf p_sec_mmz_buf = {0};

    ret = hi_tee_drv_mmz_alloc(name, size, memtype, &p_sec_mmz_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_MMZ_Alloc failed!\n");
        return HI_FAILED;
    }

    ret = hi_tee_drv_mmz_map_cpu(&p_sec_mmz_buf, cached);
    if (ret != HI_SUCCESS) {
        pr_err("drv_tee_mmz_mapCpu failed!\n");
        goto out;
    }

    ret = hi_tee_drv_mmz_unmap_cpu(&p_sec_mmz_buf);
    if (ret != HI_SUCCESS) {
        pr_err("drv_tee_mmz_unmapCpu failed!\n");
        return HI_FAILED;
    }

out:
    ret = hi_tee_drv_mmz_free(&p_sec_mmz_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_MMZ_Free failed!\n");
        return HI_FAILED;
    }

    return ret;
}

static int sec_smmu_alloc_free(const char *name, unsigned long size)
{
    int ret;
    hi_tee_smmu_buf p_sec_smmu_buf = {0};

    ret = hi_tee_drv_smmu_alloc(name, size, &p_sec_smmu_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_SMMU_Alloc failed!\n");
        return HI_FAILED;
    }

    ret = hi_tee_drv_smmu_free(&p_sec_smmu_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_SMMU_Free failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_smmu_map_unmap(const char *name, unsigned long size, int cached)
{
    int ret;
    hi_tee_smmu_buf p_sec_smmu_buf = {0};

    ret = hi_tee_drv_smmu_alloc(name, size, &p_sec_smmu_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_SMMU_Alloc failed!\n");
        return HI_FAILED;
    }

    ret = hi_tee_drv_smmu_map_cpu(&p_sec_smmu_buf, cached);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_SMMU_MapCpu failed!\n");
        goto out;
    }

    ret = hi_tee_drv_smmu_unmap_cpu(&p_sec_smmu_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_SMMU_UnmapCpu failed!\n");
        return HI_FAILED;
    }

out:
    ret = hi_tee_drv_smmu_free(&p_sec_smmu_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_SMMU_Free failed!\n");
        return HI_FAILED;
    }

    return ret;
}

static int nosec_cma_map_unmap(unsigned long addr, unsigned long size, unsigned long cached)
{
    int ret;
    hi_tee_mmz_buf p_sec_mmz_buf = {0};

    p_sec_mmz_buf.phys_addr = addr;
    p_sec_mmz_buf.size = size;
    ret = hi_tee_drv_nsmmz_map_cpu(&p_sec_mmz_buf, cached);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_NSMMZ_MapCpu failed!\n");
        return HI_FAILED;
    }

    ret = hi_tee_drv_nsmmz_unmap_cpu(&p_sec_mmz_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_NSMMZ_UmapCpu failed!\n");
        return HI_FAILED;
    }
    return HI_SUCCESS;
}

static int nosec_cma_map_unmap_secsmmu(unsigned long addr, unsigned long size)
{
    int ret;
    hi_tee_mmz_buf psMBuf = {0};
    hi_tee_smmu_buf p_sec_smmu_buf = {0};

    psMBuf.phys_addr = addr;
    ret = hi_tee_drv_mmz_map_secsmmu(&psMBuf, &p_sec_smmu_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_NSMMZ_MapSmmu failed!\n");
        return HI_FAILED;
    }

    ret = hi_tee_drv_mmz_unmap_secsmmu(&p_sec_smmu_buf, psMBuf.phys_addr);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_NSMMZ_UmapSmmu failed!\n");
        return HI_FAILED;
    }
    return HI_SUCCESS;
}

static int nosec_smmu_map_unmap(unsigned long addr, unsigned long size, unsigned long cached)
{
    int ret;
    hi_tee_smmu_buf pSmmuBuf = {0};

    pSmmuBuf.smmu_addr = addr;
    pSmmuBuf.size = size;
    ret = hi_tee_drv_nssmmu_map_cpu(&pSmmuBuf, cached);
    if (ret != HI_SUCCESS) {
        pr_err(" DRV_TEE_NSSMMU_MapCpu failed!\n");
        return HI_FAILED;
    }
    pSmmuBuf.size = size;
    ret = hi_tee_drv_nssmmu_unmap_cpu(&pSmmuBuf);
    if (ret != HI_SUCCESS) {
        pr_err(" DRV_TEE_NSSMMU_UmapCpu failed!\n");
        return HI_FAILED;
    }
    return HI_SUCCESS;
}

static int nosec_smmu_map_unmap_secsmmu(unsigned long addr, unsigned long size)
{
#if 0
    int ret;
    unsigned long sec_smmu = 0;
    hi_tee_smmu_buf pSmmuBuf = {0};

    pSmmuBuf.u32StartSmmuAddr = addr;
    ret = DRV_TEE_NSSMMU_MapSmmu(&pSmmuBuf, &sec_smmu);
    if (ret != HI_SUCCESS) {
        pr_err(" DRV_TEE_NSSMMU_MapSmmu failed!\n");
        return HI_FAILED;
    }

    pSmmuBuf.u32StartSmmuAddr = sec_smmu;
    ret = DRV_TEE_NSSMMU_UmapSmmu(&pSmmuBuf);
    if (ret != HI_SUCCESS) {
        pr_err(" DRV_TEE_NSSMMU_UmapSmmu failed!\n");
        return HI_FAILED;
    }
#endif
    return HI_SUCCESS;
}


static int sec_cma_alloc_free_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_alloc_free("test1", size, HI_SHARE_CMA, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_cma_alloc_free_more_test(unsigned long addr, unsigned long size)
{
    int ret = 0;
    int i = 0;

    for (; i < REPEAT_CNT; i++) {
        ret = sec_mmz_alloc_free("test2", size, HI_SHARE_CMA, 0);;
        if (ret != HI_SUCCESS) {
            pr_err(" call failed!\n");
            return HI_FAILED;
        }
    }

    return HI_SUCCESS;
}

static int sec_cma_alloc_free_err_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_alloc_free("test3", size, HI_SHARE_CMA, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_cma_map_unmap_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_map_unmap("test4", size, HI_SHARE_CMA, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_cma_map_unmap_more_test(unsigned long addr, unsigned long size)
{
    int ret = 0;
    int i = 0;

    for (; i < REPEAT_CNT; i++) {
        ret = sec_mmz_map_unmap("test5", size, HI_SHARE_CMA, 0);
        if (ret != HI_SUCCESS) {
            pr_err(" call failed!\n");
            return HI_FAILED;
        }
    }
    return HI_SUCCESS;
}

static int sec_cma_map_unmap_err_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_map_unmap("test6", size, HI_SHARE_CMA, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_cma_map_unmap_cache_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_map_unmap("test7", size, HI_SHARE_CMA, 1);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }
    return HI_SUCCESS;
}

static int sec_cma_map_unmap_secsmmu_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_alloc_free("test8", size, HI_SHARE_CMA, 1);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}


static int sec_cma_map_unmap_secsmmu_more_test(unsigned long addr, unsigned long size)
{
    int ret = 0;
    int i = 0;

    for (; i < REPEAT_CNT; i++) {
        ret = sec_mmz_alloc_free("test9", size, HI_SHARE_CMA, 1);
        if (ret != HI_SUCCESS) {
            pr_err(" call failed!\n");
            return HI_FAILED;
        }
    }

    return HI_SUCCESS;
}

static int sec_cma_map_unmap_secsmmu_err_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_alloc_free("test10", size, HI_SHARE_CMA, 1);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }
    return HI_SUCCESS;
}

static int sec_smmu_alloc_free_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_smmu_alloc_free("test11", size);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}


static int sec_smmu_alloc_free_more_test(unsigned long addr, unsigned long size)
{
    int ret = 0;
    int i = 0;

    for (; i < REPEAT_CNT; i++) {
        ret = sec_smmu_alloc_free("test12", size);
        if (ret != HI_SUCCESS) {
            pr_err(" call failed!\n");
            return HI_FAILED;
        }
    }

    return HI_SUCCESS;
}

static int sec_smmu_alloc_free_err_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_smmu_alloc_free("test13", size);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_smmu_map_unmap_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_smmu_map_unmap("test14", size, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_smmu_map_unmap_more_test(unsigned long addr, unsigned long size)
{
    int ret = 0;
    int i = 0;

    for (; i < REPEAT_CNT; i++) {
        ret = sec_smmu_map_unmap("test15", size, 0);
        if (ret != HI_SUCCESS) {
            pr_err(" call failed!\n");
            return HI_FAILED;
        }
    }
    return HI_SUCCESS;
}

static int sec_smmu_map_unmap_err_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_smmu_map_unmap("test16", size, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_smmu_map_unmap_chace_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_smmu_map_unmap("test17", size, 1);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_nosec_cma_map_unmap_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = nosec_cma_map_unmap(addr, size, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed !\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_nosec_cma_map_unmap_more_test(unsigned long addr, unsigned long size)
{
    int ret = 0;
    int i = 0;

    for (; i < REPEAT_CNT; i++) {
        ret = nosec_cma_map_unmap(addr, size, 0);
        if (ret != HI_SUCCESS) {
            pr_err(" call failed !\n");
            return HI_FAILED;
        }
    }

    return HI_SUCCESS;
}

static int sec_nosec_cma_map_unmap_err_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = nosec_cma_map_unmap(addr, size, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed !\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_nosec_cma_map_unmap_cache_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = nosec_cma_map_unmap(addr, size, 1);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed !\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_nosec_cma_map_unmap_secsmmu_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = nosec_cma_map_unmap_secsmmu(addr, size);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_nosec_cma_map_unmap_secsmmu_more_test(unsigned long addr, unsigned long size)
{
    int ret = 0;
    int i = 0;

    for (; i < REPEAT_CNT; i++) {
        ret = nosec_cma_map_unmap_secsmmu(addr, size);
        if (ret != HI_SUCCESS) {
            pr_err(" call failed!\n");
            return HI_FAILED;
        }
    }

    return HI_SUCCESS;
}

static int sec_nosec_cma_map_unmap_secsmmu_err_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = nosec_cma_map_unmap_secsmmu(addr, size);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_nosec_smmu_map_unmap_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = nosec_smmu_map_unmap(addr, size, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_nosec_smmu_map_unmap_more_test(unsigned long addr, unsigned long size)
{
    int ret = 0;
    int i = 0;

    for (; i < REPEAT_CNT; i++) {
        ret = nosec_smmu_map_unmap(addr, size, 0);
        if (ret != HI_SUCCESS) {
            pr_err(" call failed!\n");
            return HI_FAILED;
        }
    }

    return HI_SUCCESS;
}

static int sec_nosec_smmu_map_unmap_err_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = nosec_smmu_map_unmap(addr, size, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_nosec_smmu_map_unmap_chace_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = nosec_smmu_map_unmap(addr, size, 1);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_nosec_smmu_map_unmap_secsmmu_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = nosec_smmu_map_unmap_secsmmu(addr, size);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_nosec_smmu_map_unmap_secsmmu_more_test(unsigned long addr, unsigned long size)
{
    int ret = 0;
    int i = 0;

    for (; i < REPEAT_CNT; i++) {
        ret = nosec_smmu_map_unmap_secsmmu(addr, size);
        if (ret != HI_SUCCESS) {
            pr_err(" call failed!\n");
            return HI_FAILED;
        }
    }
    return HI_SUCCESS;
}

static int sec_nosec_smmu_map_unmap_secsmmu_err_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = nosec_smmu_map_unmap_secsmmu(addr, size);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_mmz_alloc_free_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_alloc_free("test32", size, HI_SEC_MMZ, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_mmz_alloc_free_more_test(unsigned long addr, unsigned long size)
{
    int ret = 0;
    int i = 0;

    for (; i < REPEAT_CNT; i++) {
        ret = sec_mmz_alloc_free("test33", size, HI_SEC_MMZ, 0);
        if (ret != HI_SUCCESS) {
            pr_err(" call failed!\n");
            return HI_FAILED;
        }
    }

    return HI_SUCCESS;
}

static int sec_mmz_alloc_free_err_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_alloc_free("test34", size, HI_SEC_MMZ, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_mmz_map_unmap_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_map_unmap("test35", size, HI_SEC_MMZ, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_mmz_map_unmap_more_test(unsigned long addr, unsigned long size)
{
    int ret = 0;
    int i = 0;

    for (; i < REPEAT_CNT; i++) {
        ret = sec_mmz_map_unmap("test36", size, HI_SEC_MMZ, 0);
        if (ret != HI_SUCCESS) {
            pr_err(" call failed!\n");
            return HI_FAILED;
        }
    }

    return HI_SUCCESS;
}

static int sec_mmz_map_unmap_err_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_map_unmap("test37", size, HI_SEC_MMZ, 0);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_mmz_map_unmap_cache_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_map_unmap("test38", size, HI_SEC_MMZ, 1);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_mmz_flush_test(unsigned long addr, unsigned long size)
{
    int ret;
    hi_tee_mmz_buf p_sec_mmz_buf = {0};

    ret = hi_tee_drv_mmz_alloc("test39", size,  HI_SEC_MMZ, &p_sec_mmz_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_MMZ_Alloc failed!\n");
        return HI_FAILED;
    }

    ret = hi_tee_drv_mmz_map_cpu(&p_sec_mmz_buf, 1);
    if (ret != HI_SUCCESS) {
        pr_err("drv_tee_mmz_mapCpu failed!\n");
        goto out;
    }
    if (memset_s(p_sec_mmz_buf.virt, size, 0x12, size))
        pr_err("memset failed!\n");

    ret = hi_tee_drv_mmz_unmap_cpu(&p_sec_mmz_buf);
    if (ret != HI_SUCCESS) {
        pr_err("drv_tee_mmz_unmapCpu failed!\n");
        return HI_FAILED;
    }

out:
    ret = hi_tee_drv_mmz_free(&p_sec_mmz_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_MMZ_Free failed!\n");
        return HI_FAILED;
    }

    return ret;
}

static int sec_mmz_map_unmap_secsmmu_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_alloc_free("test40", size, HI_SEC_MMZ, 1);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_mmz_map_unmap_secsmmu_more_test(unsigned long addr, unsigned long size)
{
    int ret = 0;
    int i = 0;

    for (; i < REPEAT_CNT; i++) {
        ret = sec_mmz_alloc_free("test41", size, HI_SEC_MMZ, 1);
        if (ret != HI_SUCCESS) {
            pr_err(" call failed!\n");
            return HI_FAILED;
        }
    }

    return HI_SUCCESS;
}

static int sec_mmz_map_unmap_secsmmu_err_test(unsigned long addr, unsigned long size)
{
    int ret;

    ret = sec_mmz_alloc_free("test42", size, HI_SEC_MMZ, 1);
    if (ret != HI_SUCCESS) {
        pr_err(" call failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int sec_flush_mem_test(unsigned long addr, unsigned long size)
{
    int ret;
    hi_tee_smmu_buf p_sec_smmu_buf = {0};

    ret = hi_tee_drv_smmu_alloc("test43", size, &p_sec_smmu_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_SMMU_Alloc failed!\n");
        return HI_FAILED;
    }

    ret = hi_tee_drv_smmu_map_cpu(&p_sec_smmu_buf, 1);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_SMMU_MapCpu failed!\n");
        goto out;
    }
    if (memset_s(p_sec_smmu_buf.virt, size, 0x23, size))
        pr_err("memset failed!\n");
    hi_tee_drv_mem_flush(p_sec_smmu_buf.virt, size);

    ret = hi_tee_drv_smmu_unmap_cpu(&p_sec_smmu_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_SMMU_UnmapCpu failed!\n");
        return HI_FAILED;
    }

out:
    ret = hi_tee_drv_smmu_free(&p_sec_smmu_buf);
    if (ret != HI_SUCCESS) {
        pr_err("DRV_TEE_SMMU_Free failed!\n");
        return HI_FAILED;
    }

    return ret;
}


static TEST_EVENT g_test[] = {
    {SEC_CMA_ALLOC_FREE, sec_cma_alloc_free_test},
    {SEC_CMA_ALLOC_FREE_MORE, sec_cma_alloc_free_more_test},
    {SEC_CMA_ALLOC_FREE_ERR, sec_cma_alloc_free_err_test},
    {SEC_CMA_MAP_UNMAP, sec_cma_map_unmap_test},
    {SEC_CMA_MAP_UNMAP_MORE, sec_cma_map_unmap_more_test},
    {SEC_CMA_MAP_UNMAP_ERR, sec_cma_map_unmap_err_test},
    {SEC_CMA_MAP_UNMAP_CACHE, sec_cma_map_unmap_cache_test},
    {SEC_CMA_MAP_UNMAP_SECSMMU, sec_cma_map_unmap_secsmmu_test},
    {SEC_CMA_MAP_UNMAP_SECSMMU_MORE, sec_cma_map_unmap_secsmmu_more_test},
    {SEC_CMA_MAP_UNMAP_SECSMMU_ERR, sec_cma_map_unmap_secsmmu_err_test},
    {SEC_SMMU_ALLOC_FREE, sec_smmu_alloc_free_test},
    {SEC_SMMU_ALLOC_FREE_MORE, sec_smmu_alloc_free_more_test},
    {SEC_SMMU_ALLOC_FREE_ERR, sec_smmu_alloc_free_err_test},
    {SEC_SMMU_MAP_UNMAP, sec_smmu_map_unmap_test},
    {SEC_SMMU_MAP_UNMAP_MORE, sec_smmu_map_unmap_more_test},
    {SEC_SMMU_MAP_UNMAP_ERR, sec_smmu_map_unmap_err_test},
    {SEC_SMMU_MAP_UNMAP_CACHE, sec_smmu_map_unmap_chace_test},
    {SEC_NOSEC_CMA_MAP_UNMAP, sec_nosec_cma_map_unmap_test},
    {SEC_NOSEC_CMA_MAP_UNMAP_MORE, sec_nosec_cma_map_unmap_more_test},
    {SEC_NOSEC_CMA_MAP_UNMAP_ERR, sec_nosec_cma_map_unmap_err_test},
    {SEC_NOSEC_CMA_MAP_UNMAP_CACHE, sec_nosec_cma_map_unmap_cache_test},
    {SEC_NOSEC_CMA_MAP_UNMAP_SECSMMU, sec_nosec_cma_map_unmap_secsmmu_test},
    {SEC_NOSEC_CMA_MAP_UNMAP_SECSMMU_MORE, sec_nosec_cma_map_unmap_secsmmu_more_test},
    {SEC_NOSEC_CMA_MAP_UNMAP_SECSMMU_ERR, sec_nosec_cma_map_unmap_secsmmu_err_test},
    {SEC_NOSEC_SMMU_MAP_UNMAP, sec_nosec_smmu_map_unmap_test},
    {SEC_NOSEC_SMMU_MAP_UNMAP_MORE, sec_nosec_smmu_map_unmap_more_test},
    {SEC_NOSEC_SMMU_MAP_UNMAP_ERR, sec_nosec_smmu_map_unmap_err_test},
    {SEC_NOSEC_SMMU_MAP_UNMAP_CACHE, sec_nosec_smmu_map_unmap_chace_test},
    {SEC_NOSEC_SMMU_MAP_UNMAP_SECSMMU, sec_nosec_smmu_map_unmap_secsmmu_test},
    {SEC_NOSEC_SMMU_MAP_UNMAP_SECSMMU_MORE, sec_nosec_smmu_map_unmap_secsmmu_more_test},
    {SEC_NOSEC_SMMU_MAP_UNMAP_SECSMMU_ERR, sec_nosec_smmu_map_unmap_secsmmu_err_test},
    {SEC_MMZ_ALLOC_FREE, sec_mmz_alloc_free_test},
    {SEC_MMZ_ALLOC_FREE_MORE, sec_mmz_alloc_free_more_test},
    {SEC_MMZ_ALLOC_FREE_ERR, sec_mmz_alloc_free_err_test},
    {SEC_MMZ_MAP_UNMAP, sec_mmz_map_unmap_test},
    {SEC_MMZ_MAP_UNMAP_MORE, sec_mmz_map_unmap_more_test},
    {SEC_MMZ_MAP_UNMAP_ERR, sec_mmz_map_unmap_err_test},
    {SEC_MMZ_MAP_UNMAP_CACHE, sec_mmz_map_unmap_cache_test},
    {SEC_MMZ_FLUSH, sec_mmz_flush_test},
    {SEC_MMZ_MAP_UNMAP_SECSMMU, sec_mmz_map_unmap_secsmmu_test},
    {SEC_MMZ_MAP_UNMAP_SECSMMU_MORE, sec_mmz_map_unmap_secsmmu_more_test},
    {SEC_MMZ_MAP_UNMAP_SECSMMU_ERR, sec_mmz_map_unmap_secsmmu_err_test},
    {SEC_FLUSH_MEM, sec_flush_mem_test},
};

int smmu_test(unsigned long long cmd, unsigned long long addr, unsigned size)
{
    int i = 0;
    int count;

    count = sizeof(g_test) / sizeof(TEST_EVENT);
    for (; i < count; i++) {
        if (cmd == g_test[i].cmd)
            return g_test[i].test_func(addr, size);
    }

    return HI_FAILED;
}
