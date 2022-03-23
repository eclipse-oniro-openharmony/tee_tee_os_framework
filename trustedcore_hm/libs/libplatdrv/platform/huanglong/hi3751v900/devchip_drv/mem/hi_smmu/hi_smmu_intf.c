/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: hi_smmu
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#include "hi_tee_drv_mem.h"
#include "hi_smmu.h"
#include "hi_smmu_mem.h"
#include "hi_sec_mmz.h"
#include "hi_smmu_intf.h"

#define SMMU_MEM    1
#define CMA_MEM     0
#define SHARE_MMZ   1
#define TEE_MMZ     0

/*
 * brief: alloc discontinuous mem and map to sec smmu
 * buf_name: input, the name of buffer need to alloc
 * size: input, the size of buffer need to alloc
 * smmu_buf: output, the sec smmu addr will output
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_smmu_alloc(const char *buf_name, size_t size, hi_tee_smmu_buf *smmu_buf)
{
    if (smmu_buf == NULL) {
        pr_err("output buffer is NULL!\n");
        return HI_FAILED;
    }

    smmu_buf->smmu_addr = hisi_sec_alloc(buf_name, size, SMMU_MEM);
    if (!smmu_buf->smmu_addr) {
        pr_err("alloc mem failed!\n");
        return HI_FAILED;
    }

    smmu_buf->size = size;

    return HI_SUCCESS;
}

/*
 * brief: free sec smmu buffer
 * smmu_buf: input, the buffer info
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_smmu_free(const hi_tee_smmu_buf *smmu_buf)
{
    int ret;

    if (smmu_buf == NULL) {
        pr_err("input buffer is NULL!\n");
        return HI_FAILED;
    }

    ret = hisi_sec_free(smmu_buf->smmu_addr, SMMU_MEM);
    if (ret) {
        pr_err("free mem failed, sec-smmu:0x%x!\n", smmu_buf->smmu_addr);
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

/*
 * brief: map cpu addr with sec smmu addr
 * smmu_buf: inout, sec smmu addr and size should be input, and cpu addr
 *          will be output.
 * cache: input, the cache attr when map
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_smmu_map_cpu(hi_tee_smmu_buf *smmu_buf,  bool cache)
{
    if (smmu_buf == NULL) {
        pr_err("buffer is NULL!\n");
        return HI_FAILED;
    }

    smmu_buf->virt = (void *)(uintptr_t)hisi_sec_kmap_to_cpu(smmu_buf->smmu_addr, smmu_buf->size, SMMU_MEM, cache);
    if (smmu_buf->virt == NULL) {
        pr_err("map mem failed, sec-smmu:0x%x!\n", smmu_buf->smmu_addr);
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

/*
 * brief: umap from cpu addr
 * smmu_buf: input, cpu addr of buffer should input
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_smmu_unmap_cpu(const hi_tee_smmu_buf *smmu_buf)
{
    int ret;

    if (smmu_buf == NULL) {
        pr_err("buffer is NULL!\n");
        return HI_FAILED;
    }

    ret = hisi_sec_kunmap_from_cpu(smmu_buf->virt);
    if (ret != HI_SUCCESS) {
        pr_err("unmap mem failed, sec-virt:0x%x!\n", (uintptr_t)smmu_buf->virt);
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

/*
 * brief: alloc sec mmz mem
 * bufname: input, the name of buffer need to alloc
 * size: input, the size of buffer to alloc
 * align: input, the align of buffer
 * mem_type: input, the type to separate static sec mmz or dynamic sec mmz(cma)
 * mmz_buf: output, the sec mmz addr will output
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_mmz_alloc(const char *buf_name, size_t size, hi_tee_mmz_type mem_type, hi_tee_mmz_buf *mmz_buf)
{
    if (mmz_buf == NULL) {
        pr_err("output buffer is NULL!\n");
        return HI_FAILED;
    }

    if (mem_type == HI_SHARE_CMA) {
        mmz_buf->phys_addr = hisi_sec_alloc(buf_name, size, CMA_MEM);
        if (!mmz_buf->phys_addr) {
            pr_err("alloc normal mmz mem failed!\n");
            return HI_FAILED;
        }
    } else if (mem_type == HI_SEC_MMZ) {
        mmz_buf->phys_addr = drv_tee_mmz_new("SEC-MMZ", buf_name, size);
        if (!mmz_buf->phys_addr) {
            pr_err("alloc sec mmz mem failed!\n");
            return HI_FAILED;
        }
    } else {
        pr_err("memtype :%d alloc sec mmz mem failed!\n", mem_type);
        return HI_FAILED;
    }

    mmz_buf->size = size;

    return HI_SUCCESS;
}

/*
 * brief: free mmz mem
 * mmz_buf: input, the info of buffer need to free
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_mmz_free(const hi_tee_mmz_buf *mmz_buf)
{
    int ret = HI_FAILED;

    if (mmz_buf == NULL) {
        pr_err("input buffer is NULL!\n");
        return HI_FAILED;
    }

    if (!drv_tee_mmz_is_sec(mmz_buf->phys_addr)) {
        ret = hisi_sec_free(mmz_buf->phys_addr, CMA_MEM);
        if (ret) {
            pr_err("free mem failed, sec-phys:0x%x!\n", mmz_buf->phys_addr);
            return HI_FAILED;
        }
    } else {
        drv_tee_mmz_delete(mmz_buf->phys_addr);
    }

    return HI_SUCCESS;
}

/*
 * brief: map cpu addr
 * mmz_buf: inout, the mem info
 * cached: input, the map attr of cache
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_mmz_map_cpu(hi_tee_mmz_buf *mmz_buf, bool cache)
{
    if (mmz_buf == NULL) {
        pr_err("buffer is NULL!\n");
        return HI_FAILED;
    }

    if (!drv_tee_mmz_is_sec(mmz_buf->phys_addr)) {
        mmz_buf->virt = (void *)(uintptr_t)hisi_sec_kmap_to_cpu(mmz_buf->phys_addr, mmz_buf->size, CMA_MEM, cache);
    } else {
        mmz_buf->virt = drv_tee_mmz_map(mmz_buf->phys_addr, cache);
    }
    if (mmz_buf->virt == NULL) {
        pr_err("map mem failed, phys:0x%x!\n", mmz_buf->phys_addr);
        return HI_FAILED;
    }
    return HI_SUCCESS;
}

/*
 * brief: flush cache
 * virt: input, the cpu addr
 * size: input, the size of mem
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_mem_flush(void *virt, size_t size)
{
    hisi_mem_flush(virt, size);

    return HI_SUCCESS;
}

/*
 * brief: unmap from cpu virt addr
 * mmz_buf: input, the cpu virt addr and phys addr should input
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_mmz_unmap_cpu(const hi_tee_mmz_buf *mmz_buf)
{
    int ret = HI_FAILED;

    if (mmz_buf == NULL) {
        pr_err("buffer is NULL!\n");
        return HI_FAILED;
    }

    if (!drv_tee_mmz_is_sec(mmz_buf->phys_addr)) {
        ret = hisi_sec_kunmap_from_cpu(mmz_buf->virt);
        if (ret) {
            pr_err("unmap mem failed, sec-virt:0x%x!\n", (uintptr_t)mmz_buf->virt);
            return HI_FAILED;
        }
    } else {
        ret = drv_tee_mmz_unmap(mmz_buf->virt);
        if (ret) {
            pr_err("unmap mmz mem failed!\n");
            return HI_FAILED;
        }
    }

    return HI_SUCCESS;
}

/*
 * brief: map phys addr to sec smmu addr
 * mmz_buf: input, the mem info
 * smmu_buf: output, sec smmu will output
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_mmz_map_secsmmu(const hi_tee_mmz_buf *mmz_buf, hi_tee_smmu_buf *smmu_buf)
{
    if (mmz_buf == NULL || smmu_buf == NULL) {
        pr_err("buffer is NULL!\n");
        return HI_FAILED;
    }

    if (!drv_tee_mmz_is_sec(mmz_buf->phys_addr)) {
        smmu_buf->smmu_addr = hisi_sec_map_to_sec_smmu(mmz_buf->phys_addr, mmz_buf->size, SHARE_MMZ);
    } else {
        smmu_buf->smmu_addr = drv_tee_mmz_map_to_secsmmu(mmz_buf->phys_addr, mmz_buf->size);
    }
    if (!smmu_buf->smmu_addr) {
        pr_err("map to sec smmu failed, phys:0x%x\n", smmu_buf->smmu_addr);
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

/*
 * brief: phys addr unmap from smmu addr
 * smmu_buf: input, the mem info
 * phys_addr: input, the phys addr of mem
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_mmz_unmap_secsmmu(const hi_tee_smmu_buf *smmu_buf, unsigned long phys_addr)
{
    int ret = HI_FAILED;

    if (smmu_buf == NULL || !phys_addr) {
        pr_err("buffer is NULL!\n");
        return HI_FAILED;
    }

    if (!drv_tee_mmz_is_sec(phys_addr)) {
        ret = hisi_sec_unmap_from_sec_smmu(smmu_buf->smmu_addr, SHARE_MMZ);
    } else {
        ret = drv_tee_mmz_unmap_from_secsmmu(smmu_buf->smmu_addr);
    }
    if (ret) {
        pr_err("unamp from sec smmu failed, sec-smmu:0x%x\n", smmu_buf->smmu_addr);
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

/*
 * brief: non sec mmz map to sec cpu addr
 * mmz_buf: inout, the first phys addr should input
 * cache: input, the map cache attr
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_nsmmz_map_cpu(hi_tee_mmz_buf *mmz_buf, bool cache)
{
    if (mmz_buf == NULL) {
        pr_err("buffer is NULL!\n");
        return HI_FAILED;
    }

    mmz_buf->virt = (void *)(uintptr_t)hisi_nonsec_mem_kmap_to_sec_cpu(mmz_buf->phys_addr, mmz_buf->size,
                                                                       CMA_MEM, cache);
    if (mmz_buf->virt == NULL) {
        pr_err("normal mem(cma) map to sec cpu virt failed, phys:0x%x\n", mmz_buf->phys_addr);
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

/*
 * brief: non sec mmz unmap from sec cpu addr
 * mmz_buf: input, buffer info
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_nsmmz_unmap_cpu(hi_tee_mmz_buf *mmz_buf)
{
    int ret;

    if (mmz_buf == NULL) {
        pr_err("buffer is NULL!\n");
        return HI_FAILED;
    }
    ret = hisi_nosec_mem_kunmap_from_sec_cpu(mmz_buf->virt);
    if (ret) {
        pr_err("normal mem(cma) unmap from cpu failed, sec_virt:0x%x\n", (uintptr_t)mmz_buf->virt);
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

/*
 * brief: non sec smmu mem map to sec cpu addr
 * smmu_buf: inout, the first non sec smmu should input
 * cache: input, the map cache attr
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_nssmmu_map_cpu(hi_tee_smmu_buf *smmu_buf, bool cache)
{
    if (smmu_buf == NULL) {
        pr_err("buffer is NULL!\n");
        return HI_FAILED;
    }

    smmu_buf->virt = (void *)(uintptr_t)hisi_nonsec_mem_kmap_to_sec_cpu(smmu_buf->smmu_addr, smmu_buf->size,
                                                                        SMMU_MEM, cache);
    if (smmu_buf->virt == NULL) {
        pr_err("normal mem(smmu) map to sec cpu virt failed, smmu:0x%lx\n", smmu_buf->smmu_addr);
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

/*
 * brief: non sec smmu mem unmap from sec cpu addr
 * smmu_buf: input, buffer info
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_nssmmu_unmap_cpu(hi_tee_smmu_buf *smmu_buf)
{
    int ret;

    if (smmu_buf == NULL) {
        pr_err("buffer is NULL!\n");
        return HI_FAILED;
    }
    ret = hisi_nosec_mem_kunmap_from_sec_cpu(smmu_buf->virt);
    if (ret) {
        pr_err("normal mem(smmu) unmap from cpu failed, sec_virt:0x%x\n",
               (uintptr_t)smmu_buf->virt);
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

/*
 * brief: get smmu pgt table addr and rw err addr
 * secsmmu_e_raddr: output, read addr when smmu hw read err
 * secsmmu_e_waddr: output, write addr when smmu hw write err
 * secsmmu_pgtbl: output, smmu gpt addr
 * return:
 *  0: successfully   1:failed
 */
int hi_tee_drv_smmu_get_pgtinfo(unsigned long long *secsmmu_e_raddr,
                                unsigned long long *secsmmu_e_waddr,
                                unsigned long long *secsmmu_pgtbl)
{
    if (secsmmu_e_raddr == NULL || secsmmu_e_waddr == NULL || secsmmu_pgtbl == NULL) {
        return -1;
    }

    get_sec_smmu_pgtblbase(secsmmu_e_raddr, secsmmu_e_waddr, secsmmu_pgtbl);
    return 0;
}

/*
 * brief: check if a smmu addr is sec
 * smmu_addr: input, smmu addr
 * is_sec: output, the sec attr of the smmu addr
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_smmu_is_sec(unsigned long smmu_addr, bool *is_sec)
{
    if (is_sec == NULL)
        return HI_FAILED;

    return is_sec_mem(smmu_addr, 1, (bool *)is_sec);
}

/*
 * brief: check if a phys addr is sec
 * phys_addr: input, phys addr
 * is_sec: output, the sec attr of the phys addr
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_mmz_is_sec(unsigned long phys_addr, bool *is_sec)
{
    if (is_sec == NULL) {
        return HI_FAILED;
    }

    return is_sec_mem(phys_addr, 0, (bool *)is_sec);
}

/*
 * brief: get phys addr by sec_smmu addr
 * smmu_buf: input, the sec smmu addr and size should be in it
 * mmz_buf: output, the phys addr should be got back
 * return:
 *  HI_SUCCESS, if exec successfully
 *  HI_FAILED, if exec failed
 */
int hi_tee_drv_smmu_get_mmz_by_sec_smmu(hi_tee_smmu_buf *smmu_buf, hi_tee_mmz_buf *mmz_buf)
{
    int ret;
    unsigned long long phys_addr = 0;

    if (smmu_buf == NULL || mmz_buf == NULL) {
        pr_err(" buffer is NULL!\n");
        return HI_FAILED;
    }
    ret = get_phys_by_sec_smmu(smmu_buf->smmu_addr, smmu_buf->size, &phys_addr);
    if (ret != HI_SUCCESS) {
        pr_err("get phys by sec smmu addr failed, sec_smmu:0x%x !\n", smmu_buf->smmu_addr);
        return HI_FAILED;
    }
    if (!phys_addr) {
        /* the smmu is legal, but the the mem is not continuous  */
        pr_err("cannot get phys addr");
        return HI_FAILED;
    }

    mmz_buf->phys_addr = phys_addr;
    mmz_buf->size = smmu_buf->size;

    return HI_SUCCESS;
}


int hi_tee_drv_smmu_set_tag(const hi_tee_smmu_buf *smmu_buf, unsigned int ssm_tag)
{
    return hisi_attach_smmu(smmu_buf->smmu_addr, smmu_buf->size, ssm_tag);
}

int hi_tee_drv_mem_get_secsmmu_by_handle_id(hi_tee_smmu_buf *smmu_buf, unsigned long long handle_id)
{
    unsigned long long secsmmu = 0;
    unsigned long long phys_addr = 0;
    unsigned long long size = 0;
    int ret;

    if (smmu_buf == NULL) {
        pr_err("input buffer is NULL!\n");
        return HI_FAILED;
    }

    ret = get_sec_mem_info(handle_id, &secsmmu, &phys_addr, &size);
    if (ret != HI_SUCCESS) {
        pr_err("get sec smmu failed!\n");
        return HI_FAILED;
    }

    if (secsmmu == 0) {
        pr_err(" cannot find secsmmu addr, handle_id:0x%llx \n", handle_id);
        return HI_FAILED;
    }
    smmu_buf->smmu_addr = secsmmu;
    smmu_buf->size = size;

    return HI_SUCCESS;
}

int hi_tee_drv_mem_get_secsmmz_by_handle_id(hi_tee_mmz_buf *mmz_buf, unsigned long long handle_id)
{
    unsigned long long secsmmu = 0;
    unsigned long long phys_addr = 0;
    unsigned long long size = 0;
    int ret;

    if (mmz_buf == NULL) {
        pr_err("input buffer is NULL!\n");
        return HI_FAILED;
    }

    ret = get_sec_mem_info(handle_id, &secsmmu, &phys_addr, &size);
    if (ret != HI_SUCCESS) {
        pr_err("get smmz failed!\n");
        return HI_FAILED;
    }

    if (phys_addr == 0) {
        pr_err(" cannot find smmz, handle_id:0x%llx \n", handle_id);
        return HI_FAILED;
    }

    mmz_buf->phys_addr = phys_addr;
    mmz_buf->size = size;

    return HI_SUCCESS;
}

int hi_tee_drv_mem_get_nssmmu_by_handle_id(hi_tee_smmu_buf *smmu_buf, unsigned long long handle_id)
{
    unsigned long long nssmmu;
    int ret;

    if (smmu_buf == NULL) {
        pr_err("input buffer is NULL!\n");
        return HI_FAILED;
    }
    ret = get_nssmmu_info(handle_id, &nssmmu);
    if (ret != HI_SUCCESS) {
        pr_err("get nssmmu failed!\n");
        return HI_FAILED;
    }

    smmu_buf->smmu_addr = nssmmu;

    return HI_SUCCESS;
}

int hi_tee_drv_mem_get_nsmmz_by_handle_id(hi_tee_mmz_buf *mmz_buf, unsigned long long handle_id)
{
    unsigned long long phys_addr;
    int ret;

    if (mmz_buf == NULL) {
        pr_err("input buffer is NULL!\n");
        return HI_FAILED;
    }
    ret = get_nsmmz_info(handle_id, &phys_addr);
    if (ret != HI_SUCCESS) {
        pr_err("get nsphys failed!\n");
        return HI_FAILED;
    }

    mmz_buf->phys_addr = phys_addr;

    return HI_SUCCESS;
}

