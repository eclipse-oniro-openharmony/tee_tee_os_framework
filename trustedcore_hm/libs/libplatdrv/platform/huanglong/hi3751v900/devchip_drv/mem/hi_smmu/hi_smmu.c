/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: hi_smmu
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#include "hi_smmu.h"
#include "hi_smmu_mem.h"
#include "hi_tee_drv_mem_layout.h"
#include "hi_sec_mmz.h"
#include "securec.h"
#include "hi_tee_drv_syscall_id.h"
#include "drv_legacy_def.h"
#include "hi_smmu_test.h"

#define PAGE_SHIFT              12

static void *record_buffer_every_page_info(struct tz_memblocks *tz_mblock, unsigned long long *meminfo_addr)
{
    void *virt = NULL;
    void *pageinfoaddr = NULL;
    unsigned long long meminfo_addr_temp;

    if (tz_mblock == NULL || meminfo_addr == NULL) {
        pr_err("err args, tz_mblock or meminfo_addr is NULL!\n");
        goto exit;
    }

    meminfo_addr_temp = drv_tee_mmz_new("SMMU-MMZ", "meminfo_addr",
                                        (tz_mblock->nblocks) * sizeof(struct hi_tz_pageinfo));
    if (!meminfo_addr_temp) {
        pr_err("cannot alloc mem from smmz\n");
        goto exit;
    }
    /* cache   */
    virt = drv_tee_mmz_map(meminfo_addr_temp, 1);
    if (virt == NULL) {
        pr_err("mmz map failed!\n");
        goto map_failed;
    }

    /*  cache, no sec   */
    pageinfoaddr = hi_tee_drv_hal_remap(tz_mblock->pageinfoaddr, (tz_mblock->nblocks) * sizeof(struct hi_tz_pageinfo),
                                        false, 1);
    if (pageinfoaddr == NULL) {
        pr_err("pageinfo remap failed!\n");
        goto pginfo_map_failed;
    }

    if ((memcpy_s(virt, (tz_mblock->nblocks) * sizeof(struct hi_tz_pageinfo),
                  pageinfoaddr, (tz_mblock->nblocks) * sizeof(struct hi_tz_pageinfo))) != EOK) {
        goto memcpy_s_failed;
    }

    hi_tee_drv_hal_unmap((void *)pageinfoaddr, (tz_mblock->nblocks) * sizeof(struct hi_tz_pageinfo));

    *meminfo_addr = meminfo_addr_temp;
    return virt;
memcpy_s_failed:
    hi_tee_drv_hal_unmap((void *)pageinfoaddr, (tz_mblock->nblocks) * sizeof(struct hi_tz_pageinfo));
pginfo_map_failed:
    drv_tee_mmz_unmap(virt);
map_failed:
    drv_tee_mmz_delete(meminfo_addr_temp);
    *meminfo_addr = 0;
exit:
    return NULL;
}

static struct sec_mmb *create_sec_mmb_by_tz_mblock(struct tz_memblocks *tz_mblock)
{
    struct sec_mmb *sec_mmb = NULL;
    void *virt = NULL;
    unsigned long long meminfo_addr;
    int is_secmmb_realloc = 0;

    if (tz_mblock == NULL) {
        goto exit;
    }

    sec_mmb = get_sec_mmb_by_handle_id(tz_mblock->handle_id);
    if (sec_mmb == NULL) {
        sec_mmb = (struct sec_mmb *)hi_tee_drv_hal_malloc(sizeof(struct sec_mmb));
        if (sec_mmb == NULL) {
            pr_err("hi_tee_drv_hal_malloc failed no mem!");
            goto exit;
        }
        if ((memset_s((void *)sec_mmb, sizeof(struct sec_mmb), 0x0, sizeof(struct sec_mmb))) != EOK) {
            goto out;
        }
        is_secmmb_realloc = 1;
    } else {
        is_secmmb_realloc = 0;
    }

    virt = record_buffer_every_page_info(tz_mblock, &meminfo_addr);
    if (virt == NULL || meminfo_addr == 0) {
        pr_err("record page info failed meminfo_addr:0X%llX \n", meminfo_addr);
        goto out;
    }

    sec_mmb->sec_smmu = tz_mblock->sec_smmu;
    sec_mmb->phys_addr = tz_mblock->phys_addr;
    sec_mmb->size = tz_mblock->total_size;

    sec_mmb->meminfo_addr = meminfo_addr;
    sec_mmb->tz_memblocks = tz_mblock->pageinfoaddr - sizeof(struct tz_memblocks) - tz_mblock->private_len;
    sec_mmb->nblocks = tz_mblock->nblocks;
    sec_mmb->nosec_smmu = tz_mblock->normal_smmu;
    sec_mmb->v_meminfo = virt;
    if (tz_mblock->phys_addr) {
        sec_mmb->memtype = 0;
    } else {
        sec_mmb->memtype = 1;
    }

    if (is_secmmb_realloc == 1) {
        INIT_LIST_HEAD(&sec_mmb->list);
        INIT_LIST_HEAD(&sec_mmb->t_list);
        if (insert_sec_mmb(sec_mmb) != HI_SUCCESS) {
            goto out;
        }
    }
    tz_mblock->handle_id = sec_mmb->handle_id;

    return sec_mmb;
out:
    if (is_secmmb_realloc == 1) {
        list_del(&(sec_mmb->list));
        hi_tee_drv_hal_free((void *)sec_mmb);
        sec_mmb = NULL;
    }
exit:
    return NULL;
}

static struct sec_mmb *sec_maptosmmu_with_tag(struct tz_memblocks *tz_mblock, unsigned int tag, int istagset)
{
    struct sec_mmb *sec_mmb = NULL;
    void *pageinfoaddr = NULL;
    int ret;

    if (tz_mblock == NULL) {
        pr_err("err args, tz_mblock is NULL!\n");
        goto exit;
    }

    /*  cache, no sec   */
    pageinfoaddr = hi_tee_drv_hal_remap(tz_mblock->pageinfoaddr, (tz_mblock->nblocks) * sizeof(struct hi_tz_pageinfo),
                                        false, 1);
    if (pageinfoaddr == NULL) {
        pr_err("pageinfo remap failed!\n");
        goto exit;
    }

    tz_mblock->sec_smmu = hisi_map_smmu(pageinfoaddr, (unsigned long long)tz_mblock->total_size,
                                        tz_mblock->nblocks, (tag & 0xff), tz_mblock->sec_smmu);
    if (tz_mblock->sec_smmu == INVIDE_ADDR) {
        pr_err(" hisi_map_smmu failed!\n");
        hi_tee_drv_hal_unmap((void *)pageinfoaddr, (tz_mblock->nblocks) * sizeof(struct hi_tz_pageinfo));
        goto exit;
    }
    hi_tee_drv_hal_unmap((void *)pageinfoaddr, (tz_mblock->nblocks) * sizeof(struct hi_tz_pageinfo));

    sec_mmb = create_sec_mmb_by_tz_mblock(tz_mblock);
    if (sec_mmb == NULL) {
        pr_err("create sec_mmb failed\n");
        goto out;
    }

    sec_mmb->ssm_tag = tag;
    sec_mmb->istagset = istagset;
    sec_mmb->t_ref++;
    sec_mmb->smmu_ref++;

    return sec_mmb;
out:
    hisi_unamp_smmu((unsigned long long)tz_mblock->sec_smmu, (unsigned long long)tz_mblock->total_size);
exit:
    return NULL;
}

static int sec_unmaptosmmu_with_tag(struct sec_mmb *sec_mmb)
{
    int ret;

    if (sec_mmb == NULL) {
        pr_err("sec mmb is NULL\n");
        return HI_FAILED;
    }

    hisi_unamp_smmu((unsigned long long)sec_mmb->sec_smmu, (unsigned long long)sec_mmb->size);

    ret = delete_sec_mmb(sec_mmb);
    if (ret == HI_FAILED) {
        pr_err("free sec_mmb failed!\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}


/*
 * func: map mem to sec smmu
 * tz_mblock:input, the struct tz_memblocks
 * sec_smmu:output, the sec smmu address
 * size:output, the size of sec smmu
 */
static unsigned long long sec_maptosmmu(struct tz_memblocks *tz_mblock)
{
    struct sec_mmb *sec_mmb = NULL;
    void *pageinfoaddr = NULL;
    unsigned int tag = 0;
    int istagset = 0;
    int ret;

    if (tz_mblock == NULL) {
        pr_err("err args, tz_mblock is NULL!\n");
        goto exit;
    }
    if (tz_mblock->isprivate) {
        /*
         * get tag from ssm by tz_mblock->private_data,
         * tz_mblock->private_len
         *
         */
        ret = tee_drv_ssm_check_attach_params_by_mem(tz_mblock->private_data, tz_mblock->private_len, &tag);
        if (ret) {
            pr_err("get ssm tag failed!\n");
            goto exit;
        }
        istagset = 1;
    }

    sec_mmb = sec_maptosmmu_with_tag(tz_mblock, tag, istagset);
    if (sec_mmb == NULL) {
        pr_err(" map to smmu failed\n");
        goto attach_error;
    }
    if (istagset) {
        ret = tee_drv_ssm_attach_buffer_by_mem(tz_mblock->private_data, tz_mblock->private_len, sec_mmb->sec_smmu,
                                               sec_mmb->sec_smmu + sec_mmb->size, tag);
        if (ret) {
            pr_err(" attach failed!\n");
            goto free_sec_mmb;
        }
    }

    return sec_mmb->sec_smmu;
free_sec_mmb:
    ret = sec_unmaptosmmu_with_tag(sec_mmb);
    if (ret != HI_SUCCESS) {
        pr_err("unmap smmu failed\n");
    }

attach_error:
    if (istagset) {
        tee_drv_ssm_attach_buffer_error_handle(tag);
    }
exit:
    return INVIDE_ADDR;
}

/*
 * func: unmap mem from sec smmu
 * buf_phys:input,the phy of struct tz_memblocks from no secure
 * buf_size:input,  the size of struct tz_memblocks
 */
static int sec_unmapfromsmmu(unsigned long long sec_smmu)
{
    int ret;
    struct sec_mmb *sec_mmb = NULL;
    int smmu_ref;

    if (!sec_smmu) {
        pr_err("err args, sec_smmu:0x%llx  \n", sec_smmu);
        goto exit;
    }

    sec_mmb = get_sec_mmb_by_secsmmu(sec_smmu);
    if (sec_mmb == NULL) {
        pr_err("failed, sec_smmu:0x%x \n", sec_smmu);
        goto exit;
    }
    smmu_ref = sec_mmb->smmu_ref - 1;

    if (smmu_ref) {
        goto out;
    }
    if (sec_mmb->flag) {
        ret = smmu_clear_sec_flags((unsigned long long)sec_mmb->sec_smmu, (unsigned long long)sec_mmb->size);
        if (ret == HI_FAILED) {
            pr_err("smmu_clear_sec_flags failed, sec_smmu:0x%x \n", sec_smmu);
            goto exit;
        }
    }

    /*
     * the flag is_smmu_map_clear need only to be checked after
     * clear sec flags.
     */
    if (!(sec_mmb->is_smmu_map_clear)) {
        ret = hisi_unamp_smmu((unsigned long long)sec_mmb->sec_smmu, (unsigned long long)sec_mmb->size);
        if (ret == HI_FAILED) {
            pr_err("unmap smmu failed, sec-smmu:0x%llx\n", sec_mmb->sec_smmu);
            goto exit;
        }
    }
    sec_mmb->sec_smmu = 0;
out:
    sec_mmb->smmu_ref--;
    sec_mmb->t_ref--;

    if (!sec_mmb->map_ref && !sec_mmb->smmu_ref && !sec_mmb->t_ref)
        delete_sec_mmb(sec_mmb);

    return HI_SUCCESS;

exit:
    return HI_FAILED;
}

unsigned int hisi_sec_maptosmmu(unsigned long long buf_phys, unsigned long long buf_size)
{
    struct tz_memblocks *tz_mblock = NULL;
    struct tz_memblocks tz_m;
    unsigned int va_addr;
    int ret;
    unsigned int sec_smmu;

    smmu_mutex_lock(&g_smmu_lock);
    if (!buf_phys || !buf_size) {
        pr_err("err args, buf_phys:0x%llx  buf_size:0x%llx \n", buf_phys, buf_size);
        goto exit;
    }

    /* check if the mem is secure  */
    ret = sec_mem_check(buf_phys, buf_size);
    if ((ret == SECMEMAREA) || (ret == HI_FAILED)) {
        pr_err(" The mem should be in REE ,ret:%d\n", ret);
        goto exit;
    }

    /* no secure,  cache  */
    va_addr = (unsigned int)(uintptr_t)hi_tee_drv_hal_remap((unsigned int)buf_phys, (unsigned int)buf_size, false, 1);
    if (va_addr == 0) {
        pr_err("buf map err:phys:0x%x ! \n", buf_phys);
        goto exit;
    }
    tz_mblock = (struct tz_memblocks *)(uintptr_t)va_addr;
    /* copy the data to sec mem from no sec mem    */
    if (memset_s(&tz_m, sizeof(struct tz_memblocks), 0x0, sizeof(struct tz_memblocks)))
        goto mem_out;
    if (memcpy_s(&tz_m, sizeof(struct tz_memblocks), tz_mblock, sizeof(struct tz_memblocks)))
        goto mem_out;
    sec_smmu = sec_maptosmmu(&tz_m);
    if (sec_smmu == INVIDE_ADDR) {
        pr_err("sec_maptosmmu failed!\n");
        goto mem_out;
    }

    if (memcpy_s(tz_mblock, sizeof(struct tz_memblocks), &tz_m, sizeof(struct tz_memblocks)))
        goto out;
    hi_tee_drv_hal_unmap((void *)(uintptr_t)va_addr, (unsigned int)buf_size);

    smmu_mutex_unlock(&g_smmu_lock);
    return sec_smmu;
out:
    if (sec_unmapfromsmmu(sec_smmu) == HI_FAILED) {
        pr_err("%s(%d) \n", __FUNCTION__, __LINE__);
    }
mem_out:
    hi_tee_drv_hal_unmap((void *)(uintptr_t)va_addr, (unsigned int)buf_size);
exit:
    smmu_mutex_unlock(&g_smmu_lock);
    return INVIDE_ADDR;
}

int hisi_sec_unmapfromsmmu(unsigned long long buf_phys, unsigned long long buf_size)
{
    struct tz_memblocks *tz_mblock = NULL;
    struct tz_memblocks tz_m;
    unsigned int va_addr;
    int ret;

    smmu_mutex_lock(&g_smmu_lock);
    if (!buf_phys || !buf_size) {
        pr_err("err args, buf_phys:0x%llx  buf_size:0x%llx \n", buf_phys, buf_size);
        goto exit;
    }
    /* check if the mem is secure  */
    ret = sec_mem_check(buf_phys, buf_size);
    if ((ret == SECMEMAREA) || (ret == HI_FAILED)) {
        pr_err(" The mem should be in REE ,ret:%d\n", ret);
        goto exit;
    }
    /* no secure, cache  */
    va_addr = (unsigned int)(uintptr_t)hi_tee_drv_hal_remap((unsigned int)buf_phys, (unsigned int)buf_size, false, 1);
    if (va_addr == 0) {
        pr_err("buf map err:phys:0x%x !\n", buf_phys);
        goto exit;
    }
    tz_mblock = (struct tz_memblocks *)(uintptr_t)va_addr;

    /* copy the data to sec mem from no sec mem    */
    if (memset_s(&tz_m, sizeof(struct tz_memblocks), 0x0, sizeof(struct tz_memblocks)))
        goto mem_out;
    if (memcpy_s(&tz_m, sizeof(struct tz_memblocks), tz_mblock, sizeof(struct tz_memblocks)))
        goto mem_out;

    ret = sec_unmapfromsmmu(tz_m.sec_smmu);
    if (ret == HI_FAILED) {
        pr_err("sec_unmapfromsmmu failed!\n");
        goto mem_out;
    }

    hi_tee_drv_hal_unmap((void *)(uintptr_t)va_addr, (unsigned int)buf_size);
    smmu_mutex_unlock(&g_smmu_lock);
    return HI_SUCCESS;

mem_out:
    hi_tee_drv_hal_unmap((void *)(uintptr_t)va_addr, (unsigned int)buf_size);
exit:
    smmu_mutex_unlock(&g_smmu_lock);
    return HI_FAILED;
}

static struct tz_memblocks *hisi_sec_get_memblocks(unsigned long long buf_phys, unsigned long long buf_size)
{
    int is_sec = 0;
    int ret;
    struct tz_memblocks *tz_mblock = NULL;
    void *va_addr = NULL;
    if (!buf_phys || !buf_size) {
        pr_err("err args, buf_phys:0x%lx  buf_size:0x%lx \n", buf_phys, buf_size);
        goto exit;
    }

    /* check if the mem is secure  */
    ret = sec_mem_check(buf_phys, buf_size);
    if ((ret == SECMEMAREA) || (ret == HI_FAILED)) {
        pr_err(" The mem should be in REE ,ret:%d\n", ret);
        goto exit;
    }

    /* no secure, cache  */
    va_addr = hi_tee_drv_hal_remap(buf_phys, buf_size, false, 1);
    if (va_addr == NULL) {
        pr_err("buf map err:phys:0x%lx ! \n", buf_phys);
        goto exit;
    }
    tz_mblock = (struct tz_memblocks *)(uintptr_t)va_addr;

    /* check if the mem is also secure   */
    if (!check_mem_secure_attr(tz_mblock->pageinfoaddr, tz_mblock->total_size, tz_mblock->nblocks,  &is_sec)) {
        if (is_sec) {
            pr_err("There may be something wrong,the mem is already sec.!\n");
            goto mem_out;
        }
    } else {
        pr_err("check mem failed!\n");
        goto mem_out;
    }

    return tz_mblock;
mem_out:
    hi_tee_drv_hal_unmap((void *)tz_mblock, (unsigned int)buf_size);
exit:
    return NULL;
}

struct sec_mmb *hisi_sec_maptosmmu_and_setflag(unsigned long long buf_phys, unsigned long long buf_size)
{
    struct tz_memblocks *tz_mblock = NULL;
    int ret;
    unsigned long long sec_smmu;
    struct sec_mmb *sec_mmb = NULL;

    smmu_mutex_lock(&g_smmu_lock);
    tz_mblock = hisi_sec_get_memblocks(buf_phys, buf_size);
    if (tz_mblock == NULL) {
        pr_err("%s(%d) get tz_memblocks failed \n", __FUNCTION__, __LINE__);
        goto exit;
    }

    sec_smmu = sec_maptosmmu(tz_mblock);
    if (sec_smmu == INVIDE_ADDR) {
        pr_err("sec_maptosmmu failed!\n");
        goto mem_out;
    }

    ret = smmu_set_sec_flags(sec_smmu, tz_mblock->total_size);
    if (ret == HI_FAILED) {
        pr_err("set sec flag failed, buf_phys:0x%llx sec_smmu:0x%llx\n", buf_phys, tz_mblock->sec_smmu);
        goto smmu_out;
    }
    /* set secure bitmap in mem   */
    sec_mmb = get_sec_mmb_by_secsmmu(sec_smmu);
    if (sec_mmb == NULL) {
        pr_err("get sec mem failed, sec_smmu:0x%llx \n", sec_smmu);
        goto out;
    }
    if (set_sec_mem_bitmap(sec_mmb->v_meminfo, tz_mblock->total_size)) {
        pr_err("set mem bitmap failed!\n");
        goto out;
    }

    hi_tee_drv_hal_unmap((void *)tz_mblock, (unsigned int)buf_size);

    smmu_mutex_unlock(&g_smmu_lock);

    return sec_mmb;
out:
    smmu_clear_sec_flags(sec_smmu, tz_mblock->total_size);
smmu_out:
    ret = sec_unmapfromsmmu(tz_mblock->sec_smmu);
mem_out:
    hi_tee_drv_hal_unmap((void *)tz_mblock, (unsigned int)buf_size);
exit:
    smmu_mutex_unlock(&g_smmu_lock);
    return NULL;
}

int hisi_sec_unmapfromsmmu_and_clrflg(unsigned long long buf_phys, unsigned long long buf_size)
{
    struct tz_memblocks *tz_mblock = NULL;
    int ret;

    smmu_mutex_lock(&g_smmu_lock);
    if (!buf_phys || !buf_size) {
        pr_err("err args, buf_phys:0x%x  buf_size:0x%x \n", buf_phys, buf_size);
        goto exit;
    }

    /* check if the mem is secure  */
    ret = sec_mem_check(buf_phys, buf_size);
    if ((ret == SECMEMAREA) || (ret == HI_FAILED)) {
        pr_err(" The mem should be in REE ,ret:%d\n", ret);
        goto exit;
    }

    /* no secure,  cache  */
    tz_mblock = (struct tz_memblocks *)(uintptr_t)hi_tee_drv_hal_remap(buf_phys, buf_size, false, 1);
    if (tz_mblock == NULL) {
        pr_err("buf map err:phys:0x%lx ! \n", buf_phys);
        goto exit;
    }

    ret = smmu_clear_sec_flags(tz_mblock->sec_smmu, tz_mblock->total_size);
    if (ret == HI_FAILED) {
        pr_err("clear flags failed, sec_smmu:0x%llx \n", tz_mblock->sec_smmu);
        goto mem_out;
    }

    ret = sec_unmapfromsmmu(tz_mblock->sec_smmu);
    if (ret == HI_FAILED) {
        pr_err("sec_unmapfromsmmu failed!\n");
        goto mem_out;
    }

    hi_tee_drv_hal_unmap((void *)tz_mblock, (unsigned int)buf_size);
    smmu_mutex_unlock(&g_smmu_lock);
    return HI_SUCCESS;

mem_out:
    hi_tee_drv_hal_unmap((void *)tz_mblock, (unsigned int)buf_size);
exit:
    smmu_mutex_unlock(&g_smmu_lock);
    return HI_FAILED;
}

/* alloc sec mem and return sec addr: sec_smmu or phys_addr */
unsigned long long hisi_sec_alloc(const char *bufname, unsigned long long size, int memtype)
{
    struct smmu_ctrl_t smmu_ctrl_t = {0};
    struct sec_mmb *sec_mmb = NULL;
    unsigned long long size_align;
    int ret;

    smmu_mutex_lock(&g_smmu_lock);
    /* check if size legal */
    if (size >= get_shrm_size()) {
        goto err;
    }

    size_align = ALIGN(size, HISI_SMMU_BLOCK_SIZE) + HISI_SMMU_BLOCK_SIZE;
    smmu_ctrl_t.sec_smmu  = _hisi_alloc_smmu_range(size_align);
    if (smmu_ctrl_t.sec_smmu == INVIDE_ADDR)
        goto err;

    ret = ree_ops_alloc_buffer(bufname, size, memtype, &smmu_ctrl_t);
    if (ret != HI_SUCCESS)
        goto free_smmu_range;

    smmu_mutex_unlock(&g_smmu_lock);
    sec_mmb = hisi_sec_maptosmmu_and_setflag(smmu_ctrl_t.tz_mblock_phys, sizeof(struct tz_memblocks));
    if (sec_mmb == NULL || sec_mmb->sec_smmu == INVIDE_ADDR) {
        pr_err("hisi_sec_maptosmmu_and_setflag failed!\n");
        smmu_mutex_lock(&g_smmu_lock);
        goto exit;
    }
    smmu_mutex_lock(&g_smmu_lock);

    ret = replenish_secmmb_info_by_secsmmu(sec_mmb, bufname, smmu_ctrl_t.normal_smmu);
    if (ret != HI_SUCCESS) {
        pr_err("replenish secmmb info failed\n");
        goto out;
    }

    smmu_mutex_unlock(&g_smmu_lock);
    return memtype ? sec_mmb->sec_smmu : sec_mmb->phys_addr;
out:
    smmu_mutex_unlock(&g_smmu_lock);
    if (hisi_sec_unmapfromsmmu_and_clrflg(smmu_ctrl_t.tz_mblock_phys, sizeof(struct tz_memblocks)) == HI_FAILED)
        pr_err("hisi_sec_unmapfromsmmu_and_clrflg failed!\n");
    smmu_mutex_lock(&g_smmu_lock);
exit:
    if (ree_ops_free_buffer(memtype, smmu_ctrl_t.phys_addr, smmu_ctrl_t.normal_smmu, smmu_ctrl_t.sec_smmu,
                            smmu_ctrl_t.tz_mblock_phys) != HI_SUCCESS)
        pr_err("call agent failed!\n");
free_smmu_range:
    _hisi_free_smmu_range(smmu_ctrl_t.sec_smmu, size);
err:
    smmu_mutex_unlock(&g_smmu_lock);
    pr_err("hisi_sec_alloc failed\n");
    return INVIDE_ADDR;
}

int hisi_sec_free(unsigned long long sec_addr, int memtype)
{
    unsigned long long sec_smmu;
    unsigned long long size;
    struct sec_mmb *sec_mmb = NULL;
    int ret;
    struct smmu_ctrl_t smmu_ctrl_t = {0};

    smmu_mutex_lock(&g_smmu_lock);
    /* find the mem by input addr  */
    if (memtype) {
        sec_mmb = get_sec_mmb_by_secsmmu(sec_addr);
    } else {
        sec_mmb = get_sec_mmb_by_phys(sec_addr);
    }

    if (sec_mmb == NULL) {
        pr_err("cannot find sec mem, memtype:0x%x, sec_addr:0x%llx\n", memtype, sec_addr);
        goto out;
    }

    sec_smmu = sec_mmb->sec_smmu;
    size = sec_mmb->size;
    smmu_ctrl_t.cmd = HISI_MEM_FREE;
    smmu_ctrl_t.memtype = memtype;
    smmu_ctrl_t.sec_smmu = sec_smmu;
    smmu_ctrl_t.normal_smmu = sec_mmb->nosec_smmu;
    smmu_ctrl_t.phys_addr = sec_mmb->phys_addr;
    smmu_ctrl_t.tz_mblock_phys = sec_mmb->tz_memblocks;
    smmu_ctrl_t.handle_id = sec_mmb->handle_id;
    if (!memtype)
        smmu_ctrl_t.phys_addr = sec_addr;

    ret = smmu_clear_sec_flags(sec_smmu, size);
    if (ret == HI_FAILED) {
        pr_err("clear flags failed, sec_addr:0x%x  memtype:%d\n", sec_addr, memtype);
        goto out;
    }

    ret = sec_unmapfromsmmu(sec_smmu);
    if (ret == HI_FAILED) {
        pr_err("sec_unmapfromsmmu failed!\n");
        goto out;
    }

    ret = hi_tee_drv_hal_agentcall(SMMU_AGENT_ID, TA_CALL_AGENT, (void *)(&smmu_ctrl_t), sizeof(struct smmu_ctrl_t));
    if (ret != HI_SUCCESS) {
        pr_err("%s(%d) call failed, ret = %d  \n", __FUNCTION__, __LINE__, ret);
        goto out;
    }

    smmu_mutex_unlock(&g_smmu_lock);
    return HI_SUCCESS;
out:
    smmu_mutex_unlock(&g_smmu_lock);
    return HI_FAILED;
}

static int check_sec_usr_mem_area(unsigned long long sec_uaddr, unsigned int datalen,
                                  int memtype, struct sec_mmb *sec_mmb)
{
    long long dataend;

    /* check the user mem area whether to be legal
     * the sec_addr is checked in get_sec_mmb_by_XXX and just
     * check the size here
     * The sec_mmb->sec_smmu + sec_mmb->size can not be overflow,
     * or the mem should not be allocated successfully.
     */
    if (!datalen) {
        pr_err("The datalen must not be zero!\n");
        return HI_FAILED;
    }
    /*  avoid overflow   */
    dataend = (long long)sec_uaddr;
    dataend = dataend + (long long)datalen;
    if (datalen > sec_mmb->size) {
        pr_err("The datalen(0x%x) is too long, the max mem size is \
                0x%llx \n", datalen, sec_mmb->size);
        return HI_FAILED;
    }
    if (memtype) {
        if (dataend > (long long)(sec_mmb->sec_smmu + sec_mmb->size)) {
            pr_err("The user mem area is overflow. userstart:0x%llx \
                datalen 0x%x, mmbstart:0x%x mmbsize:0x%x \n",
                sec_uaddr, datalen, sec_mmb->sec_smmu,
                sec_mmb->size);
            return HI_FAILED;
        }
    } else {
        if (dataend > (long long)(sec_mmb->phys_addr + sec_mmb->size)) {
            pr_err("The user mem area is overflow. userstart:0x%x \
                datalen 0x%x, mmbstart:0x%x mmbsize:0x%x \n",
                sec_uaddr, datalen, sec_mmb->phys_addr,
                sec_mmb->size);
            return HI_FAILED;
        }
    }

    return HI_SUCCESS;
}

/* map to sec cpu  */
unsigned int hisi_sec_kmap_to_cpu(unsigned long long sec_addr, unsigned int datalen, int memtype, int cached)
{
    struct sec_mmb *sec_mmb = NULL;
    void *virt = NULL;
    unsigned int cpu_virt;
    unsigned int offset;
    bool secmode = false;

    smmu_mutex_lock(&g_smmu_lock);
    if (memtype) {
        sec_mmb = get_sec_mmb_by_secsmmu(sec_addr);
    } else {
        sec_mmb = get_sec_mmb_by_phys(sec_addr);
    }
    if (sec_mmb == NULL) {
        pr_err("cannot find sec mem, sec_addr:0x%llx , \
                memtype:0x%x\n", sec_addr, memtype);
        goto exit;
    }

    /* check user mem area   */
    if (check_sec_usr_mem_area(sec_addr, datalen, memtype, sec_mmb) != HI_SUCCESS) {
        goto exit;
    }
    if (!sec_mmb->kmap_ref) {
        secmode = sec_mmb->flag ? true : false;
        virt = hisi_map_cpu(sec_mmb->v_meminfo, sec_mmb->nblocks, sec_mmb->size, secmode, cached);
        if (virt == NULL) {
            pr_err("map to cpu failed,sec_addr:0x%x memtype:%d\n", sec_addr, memtype);
            goto exit;
        }
        sec_mmb->sec_virt = virt;
        sec_mmb->cached = cached;
    } else {
        if (sec_mmb->cached != cached) {
            pr_err("the cache attr is not match, sec_addr:0x%x memtype:%d  cached:%d sec_mmb:%d\n", sec_addr, memtype,
                   cached, sec_mmb->cached);
            goto exit;
        }
    }

    sec_mmb->kmap_ref++;
    sec_mmb->map_ref++;
    sec_mmb->t_ref++;

    offset = (memtype) ? (sec_addr - sec_mmb->sec_smmu) : (sec_addr - sec_mmb->phys_addr);

    cpu_virt = (unsigned int)(uintptr_t)sec_mmb->sec_virt + offset;

    smmu_mutex_unlock(&g_smmu_lock);
    return cpu_virt;

exit:
    smmu_mutex_unlock(&g_smmu_lock);
    return (unsigned int)NULL;
}

/* unmap from sec cpu */
int hisi_sec_kunmap_from_cpu(void *sec_virt)
{
    struct sec_mmb *sec_mmb = NULL;
    int tmp_map_ref;

    smmu_mutex_lock(&g_smmu_lock);
    sec_mmb = get_sec_mmb_by_secvirt(sec_virt);
    if (sec_mmb == NULL) {
        pr_err("cannot find sec mem, virt:0x%x\n", (uintptr_t)sec_virt);
        goto exit;
    }

    tmp_map_ref = sec_mmb->kmap_ref - 1;
    if (!tmp_map_ref) {
        if (sec_mmb->cached) {
            smmu_flush_cache_area(sec_mmb->sec_virt, sec_mmb->size);
            sec_mmb->cached = 0;
        }
        hisi_unmap_cpu(sec_mmb->sec_virt, sec_mmb->size, true);
        sec_mmb->sec_virt = NULL;
    }

    sec_mmb->kmap_ref--;
    sec_mmb->map_ref--;
    sec_mmb->t_ref--;

    if (!sec_mmb->map_ref && !sec_mmb->smmu_ref && !sec_mmb->t_ref)
        delete_sec_mmb(sec_mmb);
    smmu_mutex_unlock(&g_smmu_lock);
    return HI_SUCCESS;
exit:
    smmu_mutex_unlock(&g_smmu_lock);
    return HI_FAILED;
}

/* get sec smmu by phys_addr in sec share mem
 * it has been also map to sec smmu
 */
static unsigned long long sec_share_mem_map_to_sec_smmu(unsigned long long phys_addr)
{
    struct sec_mmb *sec_mmb = NULL;
    unsigned long long offset;

    sec_mmb = get_sec_mmb_by_phys(phys_addr);
    if (sec_mmb == NULL) {
        pr_err("cannot find sec mem, phys:0x%llx\n", phys_addr);
        goto exit;
    }

    sec_mmb->t_ref++;
    sec_mmb->smmu_ref++;

    offset = phys_addr - sec_mmb->phys_addr;

    return (sec_mmb->sec_smmu + offset);
exit:
    return INVIDE_ADDR;
}

/*
 * only for sec-mmz in secure os
 */
static unsigned long long sec_mmz_map_to_sec_smmu(unsigned long long phys_addr,
                                                  unsigned long long size, unsigned int tag)
{
    struct sec_mmb *sec_mmb = NULL;
    unsigned long long sec_smmu;
    unsigned long long offset;
    unsigned long long phys;

    sec_mmb = get_sec_mmb_by_phys(phys_addr);
    if (sec_mmb != NULL) {
        sec_mmb->t_ref++;
        sec_mmb->smmu_ref++;
        sec_smmu = sec_mmb->sec_smmu;
        offset = phys_addr - sec_mmb->phys_addr;

        goto out;
    }

    /* mmz must be aligned to 4K    */
    phys = ROUNDDOWN(phys_addr, SZ_4K);
    size = ROUNDUP(phys_addr + size, SZ_4K) - phys;
    offset = phys_addr - phys;

    sec_smmu = hisi_map_smmu_by_phys(phys, size, tag);
    if (sec_smmu == INVIDE_ADDR) {
        pr_err("map smmu failed!\n");
        goto exit;
    }

    sec_mmb = (struct sec_mmb *)hi_tee_drv_hal_malloc(sizeof(struct sec_mmb));
    if (sec_mmb == NULL) {
        pr_err("hi_tee_drv_hal_malloc failed no mem!");
        goto mem_err;
    }
    if (memset_s((void *)sec_mmb, sizeof(struct sec_mmb), 0x0, sizeof(struct sec_mmb)))
        goto memset_failed;

    sec_mmb->sec_smmu = sec_smmu;
    sec_mmb->phys_addr = phys;
    sec_mmb->size = size;

    sec_mmb->t_ref++;
    sec_mmb->smmu_ref++;

    INIT_LIST_HEAD(&sec_mmb->list);
    INIT_LIST_HEAD(&sec_mmb->t_list);

    if (insert_sec_mmb(sec_mmb) != HI_SUCCESS) {
        goto memset_failed;
    }
out:
    return (sec_smmu + offset);
memset_failed:
    hi_tee_drv_hal_free((void *)sec_mmb);
mem_err:
    hisi_unamp_smmu(sec_smmu, size);
exit:
    return INVIDE_ADDR;
}


/*
 * phys_addr: phys_addr of the mem
 * size: the mem size
 * share_mem: 1:share mem   0: sec-mmz
 *
 */
unsigned int hisi_sec_map_to_sec_smmu(unsigned long long phys_addr, unsigned long long size, int share_mem)
{
    unsigned long long sec_smmu;

    smmu_mutex_lock(&g_smmu_lock);
    if (!phys_addr || !size) {
        pr_err("err args, phys_addr:0x%llx size:0x%llx\n", phys_addr, size);
        smmu_mutex_unlock(&g_smmu_lock);
        return INVIDE_ADDR;
    }

    if (share_mem) {
        sec_smmu = sec_share_mem_map_to_sec_smmu(phys_addr);
    } else {
        sec_smmu = sec_mmz_map_to_sec_smmu(phys_addr, size, 0);
    }
    smmu_mutex_unlock(&g_smmu_lock);
    return sec_smmu;
}

/*
 * sec_smmu: sec smmu address
 * share_mem: !: share mem   0:sec-mmz
 */
int hisi_sec_unmap_from_sec_smmu(unsigned long long sec_smmu, int share_mem)
{
    int ret;
    smmu_mutex_lock(&g_smmu_lock);
    ret = sec_unmapfromsmmu(sec_smmu);
    if (ret == HI_FAILED) {
        pr_err("sec_smmu:0x%llx  share_mem:%d \n", sec_smmu, share_mem);
        (void *)share_mem;
    }
    smmu_mutex_unlock(&g_smmu_lock);
    return ret;
}

/*  no sec mem     */
static struct sec_mmb *alloc_new_sec_mmb(unsigned long long nonsec_addr, int memtype)
{
    struct smmu_ctrl_t smmu_ctrl_t = {0};
    struct sec_mmb *sec_mmb = NULL;
    struct tz_memblocks *tz_mblock = NULL;
    unsigned int va_addr;
    unsigned long long buf_phys;
    int ret;

    ret = ree_mmz_ops_get_meminfo(nonsec_addr, memtype, &smmu_ctrl_t);
    if (ret != HI_SUCCESS || !(smmu_ctrl_t.tz_mblock_phys)) {
        pr_err("ree mmz ops get meminfo failed phys:0x%lx\n", smmu_ctrl_t.tz_mblock_phys);
        goto out;
    }
    buf_phys = smmu_ctrl_t.tz_mblock_phys;

    /* check if the mem is secure  */
    ret = sec_mem_check(buf_phys, sizeof(struct tz_memblocks));
    if ((ret == SECMEMAREA) || (ret == HI_FAILED)) {
        pr_err(" The mem should be in REE ,ret:%d\n", ret);
        goto exit;
    }

    va_addr = (unsigned int)(uintptr_t)hi_tee_drv_hal_remap((unsigned int)buf_phys,
                                                            (unsigned int)sizeof(struct tz_memblocks), false, 1);
    if (va_addr == 0) {
        pr_err("buf map err:phys:0x%x ! \n", buf_phys);
        goto exit;
    }
    tz_mblock = (struct tz_memblocks *)(uintptr_t)va_addr;
    sec_mmb = create_sec_mmb_by_tz_mblock(tz_mblock);
    if (sec_mmb == NULL) {
        pr_err("create sec_mmb failed\n");
        goto create_err;
    }

    hi_tee_drv_hal_unmap((void *)(uintptr_t)va_addr, (unsigned int)sizeof(struct tz_memblocks));

    return sec_mmb;

create_err:
    hi_tee_drv_hal_unmap((void *)(uintptr_t)va_addr, (unsigned int)sizeof(struct tz_memblocks));
exit:
    ret = ree_mmz_ops_put_meminfo(smmu_ctrl_t.phys_addr, smmu_ctrl_t.normal_smmu,
                                  smmu_ctrl_t.memtype, smmu_ctrl_t.tz_mblock_phys,
                                  smmu_ctrl_t.handle_id);
    if (ret != HI_SUCCESS) {
        pr_err("ree mmz ops put  failed!\n");
    }

out:
    return NULL;
}

static int free_new_sec_mmb(struct sec_mmb *sec_mmb)
{
    struct smmu_ctrl_t smmu_ctrl_t;
    int ret;

    if (sec_mmb == NULL) {
        pr_err("err args\n");
        return -1;
    }
    if (memset_s((void *)(&smmu_ctrl_t), sizeof(struct smmu_ctrl_t), 0x0, sizeof(struct smmu_ctrl_t)))
        return -1;
    smmu_ctrl_t.memtype = sec_mmb->memtype;
    smmu_ctrl_t.tz_mblock_phys = sec_mmb->tz_memblocks;
    smmu_ctrl_t.normal_smmu = sec_mmb->nosec_smmu;
    smmu_ctrl_t.phys_addr = sec_mmb->phys_addr;
    smmu_ctrl_t.sec_smmu = sec_mmb->sec_smmu;
    smmu_ctrl_t.cmd = HISI_MEM_PUT_MEMINFO;
    smmu_ctrl_t.handle_id = sec_mmb->handle_id;
    ret = hi_tee_drv_hal_agentcall(SMMU_AGENT_ID, TA_CALL_AGENT, (void *)(&smmu_ctrl_t), sizeof(struct smmu_ctrl_t));
    if (ret != HI_SUCCESS) {
        pr_err("%s(%d) call failed, ret = %d  \n", __FUNCTION__, __LINE__, ret);
        goto err;
    }

    if (delete_sec_mmb(sec_mmb) == HI_FAILED) {
        pr_err("%s(%d) \n", __FUNCTION__, __LINE__);
    }

    return HI_SUCCESS;
err:
    return HI_FAILED;
}


static int check_nosec_usr_mem_area(unsigned long long uaddr, unsigned int datalen,
                                    int memtype, struct sec_mmb *sec_mmb)
{
    long long dataend;

    /* check the user mem area wether to be legal
     * the sec_addr is checked in get_sec_mmb_by_XXX and just
     * check the size here
     * The sec_mmb->sec_smmu + sec_mmb->size can not be overflow,
     * or the mem should not be allocated successfully.
     */
    if (!datalen) {
        pr_err("The datalen must not be zero!\n");
        return -1;
    }
    /*  avoid overflow   */
    dataend = (long long)uaddr;
    dataend = dataend + (long long)datalen;
    if (datalen > sec_mmb->size) {
        pr_err("The datalen(0x%x) is too long, the max mem size is \
                0x%llx \n", datalen, sec_mmb->size);
        return -1;
    }
    if (memtype) {
        if (dataend > (long long)(sec_mmb->nosec_smmu + sec_mmb->size)) {
            pr_err("The user mem area is overflow. userstart:0x%llx \
                datalen 0x%x, mmbstart:0x%llx mmbsize:0x%llx \n",
                uaddr, datalen, sec_mmb->nosec_smmu,
                sec_mmb->size);
            return -1;
        }
    } else {
        if (dataend > (long long)(sec_mmb->phys_addr + sec_mmb->size)) {
            pr_err("The user mem area is overflow. userstart:0x%x \
                datalen 0x%x, mmbstart:0x%llx mmbsize:0x%llx \n",
                uaddr, datalen, sec_mmb->phys_addr,
                sec_mmb->size);
            return -1;
        }
    }

    return 0;
}

static int hisi_nonsec_mem_kmap_to_sec_cpu_check_secmmb(unsigned long long nonsec_addr,
    unsigned int datalen, int memtype, struct sec_mmb *sec_mmb, int cached)
{
    bool secmode = false;
    int ret;
    /* check user mem  area  */
    ret = check_nosec_usr_mem_area(nonsec_addr, datalen, memtype, sec_mmb);
    if (ret != 0) {
        return HI_FAILED;
    }

    if (!sec_mmb->kmap_ref) {
        secmode = (sec_mmb->flag) ? true : false;
        sec_mmb->sec_virt = hisi_map_cpu(sec_mmb->v_meminfo, sec_mmb->nblocks,
                                         sec_mmb->size, secmode, cached);
        if (sec_mmb->sec_virt == NULL) {
            pr_err("map sec cpu failed!\n");
            return HI_FAILED;
        }
        sec_mmb->cached = cached;
    } else {
        if (sec_mmb->cached != cached) {
            pr_err("the cache attr is not match, cached:%d sec_mmb:%d\n", cached, sec_mmb->cached);
            return HI_FAILED;
        }
    }
    return HI_SUCCESS;
}

struct sec_mmb *create_sec_mmb_by_nosec_addr(unsigned long long nonsec_addr,
    unsigned int datalen, int memtype, int cached)
{
    struct sec_mmb *sec_mmb = NULL;
    int ret;
    bool secmode = false;

    sec_mmb = alloc_new_sec_mmb(nonsec_addr, memtype);
    if (sec_mmb == NULL) {
        pr_err("alloc sec mmb failed, nonsec_addr:0x%llx memtype:%d\n", nonsec_addr, memtype);
        goto exit;
    }
    /* check user mem  area  */
    ret = check_nosec_usr_mem_area(nonsec_addr, datalen, memtype, sec_mmb);
    if (ret != 0) {
        goto failed;
    }

    secmode = ((sec_mmb)->flag) ? true : false;
    sec_mmb->sec_virt = hisi_map_cpu(sec_mmb->v_meminfo, sec_mmb->nblocks, sec_mmb->size, secmode, cached);
    if (sec_mmb->sec_virt == NULL) {
        pr_err("map sec cpu failed, nosecaddr:0x%x  memtype:0x%x\n", nonsec_addr, memtype);
        goto failed;
    }

    sec_mmb->cached = cached;

    return sec_mmb;

failed:
    if (delete_sec_mmb(sec_mmb) == HI_FAILED) {
        pr_err("%s(%d) \n", __FUNCTION__, __LINE__);
    }
exit:
    return NULL;
}
/*
 * nosec_addr: no sec addr, cma phys addr or nonsec smmu
 * memtype: the nosec_addr address type, 1 nonsec smmu, 0 cma phys addr
 * cached: the cache attr when to map cpu
 */
unsigned int hisi_nonsec_mem_kmap_to_sec_cpu(unsigned long long nonsec_addr,
                                             unsigned int datalen, int memtype, int cached)
{
    struct sec_mmb *sec_mmb = NULL;
    unsigned long long offset;
    int ret = -1;

    smmu_mutex_lock(&g_smmu_lock);

    if (memtype == 0) {
        sec_mmb = get_sec_mmb_by_phys(nonsec_addr);
    } else {
        sec_mmb = get_sec_mmb_by_nosecsmmu(nonsec_addr);
    }

    if (sec_mmb != NULL) {
        ret = hisi_nonsec_mem_kmap_to_sec_cpu_check_secmmb(nonsec_addr, datalen, memtype, sec_mmb, cached);
        if (ret == HI_FAILED) {
            pr_err("check secmmb failed, nosecaddr:0x%llx memtype:0x%x cached:%d\n", nonsec_addr,
                   memtype, cached);
            goto err;
        }
        goto out;
    }

    sec_mmb = create_sec_mmb_by_nosec_addr(nonsec_addr, datalen, memtype, cached);
    if (sec_mmb == NULL) {
        pr_err("add sec_mmb to list failed, nonsec_addr:0x%x memtype:%d cached:%d\n", nonsec_addr,
               memtype, cached);
        goto err;
    }

out:
    sec_mmb->kmap_ref++;
    sec_mmb->t_ref++;
    sec_mmb->map_ref++;
    offset = (memtype) ? (nonsec_addr - sec_mmb->nosec_smmu) : (nonsec_addr - sec_mmb->phys_addr);
    smmu_mutex_unlock(&g_smmu_lock);

    return ((unsigned int)(uintptr_t)sec_mmb->sec_virt + offset);
err:
    smmu_mutex_unlock(&g_smmu_lock);
    return (unsigned int)NULL;
}

int hisi_nosec_mem_kunmap_from_sec_cpu(void *va_addr)
{
    struct sec_mmb *sec_mmb = NULL;
    int map_ref;

    smmu_mutex_lock(&g_smmu_lock);
    sec_mmb = get_sec_mmb_by_secvirt(va_addr);
    if (sec_mmb == NULL) {
        pr_err("err args, sec_virt:0x%x  \n", (uintptr_t)va_addr);
        smmu_mutex_unlock(&g_smmu_lock);
        return HI_FAILED;
    }
    map_ref = sec_mmb->kmap_ref - 1;
    if (!map_ref) {
        if (sec_mmb->cached) {
                smmu_flush_cache_area(sec_mmb->sec_virt, sec_mmb->size);
            sec_mmb->cached = 0;
        }
        hisi_unmap_cpu(sec_mmb->sec_virt, sec_mmb->size, false);
        sec_mmb->sec_virt = NULL;
    }
    sec_mmb->kmap_ref--;
    sec_mmb->t_ref--;
    sec_mmb->map_ref--;

    if (!sec_mmb->map_ref && !sec_mmb->smmu_ref && !sec_mmb->t_ref)
        free_new_sec_mmb(sec_mmb);

    smmu_mutex_unlock(&g_smmu_lock);
    return HI_SUCCESS;
}

int agent_closed(void)
{
    struct smmu_ctrl_t smmu_ctrl_t;
    int ret;

    /* release sec mmb
     * because share mem (system or cma) must be free successfully first,
     * then the sec_mmb struct will be free. If there are some sec_mmb struct
     * means some mem is not free, and agent exit is not called in REE
     **/
    smmu_mutex_lock(&g_smmu_lock);

    if (memset_s((void *)(&smmu_ctrl_t), sizeof(struct smmu_ctrl_t), 0x0, sizeof(struct smmu_ctrl_t)))
        goto err;
    smmu_ctrl_t.cmd = HISI_AGENT_CLOSE;
    ret = hi_tee_drv_hal_agentcall(SMMU_AGENT_ID, TA_CALL_AGENT, (void *)(&smmu_ctrl_t), sizeof(struct smmu_ctrl_t));
    if (ret != HI_SUCCESS) {
        pr_err("%s(%d) call failed, ret = %d  \n", __FUNCTION__, __LINE__, ret);
        goto err;
    }

    smmu_mutex_unlock(&g_smmu_lock);

    return 0;
err:
    smmu_mutex_unlock(&g_smmu_lock);
    return -1;
}

int sec_ioctl(unsigned long long cmd, unsigned long long arg0, unsigned long long arg1)
{
    int ret = HI_FAILED;
    unsigned long long cmd_s = cmd;
#if 1
    unsigned long long arg0_s = arg0;
    unsigned long long arg1_s = arg1;

    if (cmd < HI_MEM_PROC)
        return smmu_test(cmd_s, arg0_s, arg1_s);
#else
    (void *)arg0;
    (void *)arg1;
#endif
    switch (cmd_s) {
        case HI_MEM_PROC:
            smmu_mutex_lock(&g_smmu_lock);
            dump_mem();
            smmu_mutex_unlock(&g_smmu_lock);
            ret = HI_SUCCESS;
            break;
        default:
            pr_err("Invalid CMD :%llx\n", cmd);
            ret = HI_FAILED;
    }

    return ret;
}

void hisi_mem_flush(void *virt, unsigned long long size)
{
    smmu_flush_cache_area(virt, size);
}

int get_phys_by_sec_smmu(unsigned long long sec_smmu, unsigned long long size, unsigned long long *phys_addr)
{
    int ret;
    struct sec_mmb *sec_mmb = NULL;
    unsigned long long offset;

    smmu_mutex_lock(&g_smmu_lock);
    sec_mmb = get_sec_mmb_by_secsmmu(sec_smmu);
    if (sec_mmb == NULL) {
        pr_err("cannot find the mem by sec_smmu:0x%llx \n", sec_smmu);
        goto exit;
    }
    if (check_sec_usr_mem_area(sec_smmu, size, 1, sec_mmb) != HI_SUCCESS) {
        pr_err("mem check failed!\n");
        goto exit;
    }
    if (!(sec_mmb->phys_addr)) {
        /*
         * The mem is not continuous mem.
         * The phys_addr should be checked when used.
         */
        *phys_addr = 0;
        goto out;
    }

    offset = sec_smmu - sec_mmb->sec_smmu;
    *phys_addr = sec_mmb->phys_addr + offset;
out:
    ret = HI_SUCCESS;

exit:
    smmu_mutex_unlock(&g_smmu_lock);

    return ret;
}

int is_sec_mem(unsigned int addr, int iommu, bool *is_sec)
{
    struct sec_mmb *sec_mmb = NULL;
    int ret = HI_FAILED;

    smmu_mutex_lock(&g_smmu_lock);
    if (iommu) {
        /* smmu addr   */
        sec_mmb = get_sec_mmb_by_secsmmu(addr);
        if (sec_mmb == NULL) {
            /* can not find sec smmu   */
            ret = HI_SUCCESS;
            *is_sec = false;
            goto out;
        }
        /* check if sec-mmz area */
        if (sec_mmb->phys_addr) {
            if (drv_tee_mmz_is_sec(sec_mmb->phys_addr)) {
                *is_sec = true;
                ret = HI_SUCCESS;
                goto out;
            }
        }

        ret = HI_SUCCESS;
        *is_sec = (sec_mmb->flag) ? true : false;
        goto out;
    } else {
        ret = phy_area_available_check(addr, 0, TOTAL_MEM_RANGE);
        if (ret == HI_FAILED) {
            pr_err("invalid addr:phys:0x%x \n", addr);
            goto out;
        }

        ret = phy_area_available_check(addr, 0, SEC_MEM_RANGE);
        if (ret == HI_SUCCESS) {
            pr_err("invalid addr:phys:0x%x \n", addr);
            *is_sec = true;
            goto out;
        }

        sec_mmb = get_sec_mmb_by_phys(addr);
        if (sec_mmb == NULL) {
            ret = HI_SUCCESS;
            *is_sec = false;
            goto out;
        }

        ret = HI_SUCCESS;
        *is_sec = (sec_mmb->flag) ? true : false;
        goto out;
    }

out:
    smmu_mutex_unlock(&g_smmu_lock);

    return ret;
}

int hisi_attach_smmu(unsigned long long secsmmu, unsigned long long size, unsigned int ssm_tag)
{
    struct sec_mmb *sec_mmb = NULL;
    int ret;

    smmu_mutex_lock(&g_smmu_lock);
    sec_mmb = get_sec_mmb_by_secsmmu(secsmmu);
    if (sec_mmb == NULL) {
        ret = HI_FAILED;
        pr_err("%s, cannot find mem, secsmmu:0x%llx ,attach failed\n", __func__, secsmmu);
        goto out;
    }
    if (sec_mmb->istagset) {
        if ((sec_mmb->ssm_tag & 0xff) == (ssm_tag & 0xff)) { /* 0xff just compare the low byte */
            ret = HI_SUCCESS;
            pr_debug("the same ssm_tag ,do not do the same thing\n");
        } else {
            ret = HI_FAILED;
            pr_err("already attached ,cannot do it again\n");
        }
        goto out;
    }

    ret = hisi_update_pagetable(sec_mmb->sec_smmu, sec_mmb->size, ssm_tag & 0xff);
    if (ret) {
        pr_err("attach failed!\n");
        goto out;
    }
    sec_mmb->ssm_tag = ssm_tag;
    sec_mmb->istagset = 1;
out:
    smmu_mutex_unlock(&g_smmu_lock);
    return ret;
}

int get_sec_mem_info(unsigned long long handle_id, unsigned long long *secsmmu,
                     unsigned long long *phys_addr, unsigned long long *size)
{
    struct sec_mmb *sec_mmb = NULL;
    int ret;

    if ((secsmmu == NULL) || (phys_addr == NULL) || (size == NULL)) {
        return HI_FAILED;
    }

    smmu_mutex_lock(&g_smmu_lock);
    sec_mmb = get_sec_mmb_by_handle_id(handle_id);
    if (sec_mmb == NULL) {
        pr_err("cannot find invalid buffer, handle_id:0x%llx\n", handle_id);
        smmu_mutex_unlock(&g_smmu_lock);
        return HI_FAILED;
    }

    *secsmmu = sec_mmb->sec_smmu;
    *phys_addr = sec_mmb->phys_addr;
    *size = sec_mmb->size;

    smmu_mutex_unlock(&g_smmu_lock);
    return HI_SUCCESS;
}

int get_nssmmu_info(unsigned long long handle_id, unsigned long long *nssmmu)
{
    if (nssmmu == NULL)
        return HI_FAILED;

    *nssmmu = handle_id;
    return HI_SUCCESS;
}

int get_nsmmz_info(unsigned long long handle_id, unsigned long long *phys_addr)
{
    if (phys_addr == NULL)
        return HI_FAILED;

    *phys_addr = handle_id;
    return HI_SUCCESS;
}

int get_handle_id(unsigned long long secsmmu, unsigned long long *handle_id)
{
    int ret;
    struct sec_mmb *sec_mmb = NULL;

    if (handle_id == NULL)
        return HI_FAILED;

    smmu_mutex_lock(&g_smmu_lock);
    sec_mmb = get_sec_mmb_by_secsmmu(secsmmu);
    if (sec_mmb == NULL) {
        pr_err("cannot find invalid buffer, secsmmu:0x%llx\n", secsmmu);
        smmu_mutex_unlock(&g_smmu_lock);
        return HI_FAILED;
    }
    smmu_mutex_unlock(&g_smmu_lock);
    *handle_id = sec_mmb->handle_id;

    return HI_SUCCESS;
}

static int hi_smmu_driver_w(int op, struct hi_tee_smmu_ioctl_data *buf_local)
{
    char mmb_name[HIL_MAX_NAME_LEN];
    struct sec_mmb *sec_mmb = NULL;
    unsigned long long addr = 0;
    int name_len = 0;
    int res = HI_FAILED;

    switch (op) {
        case HISI_SEC_ALLOC:
            name_len = strlen(buf_local->bufname) + 1;
            if ((memcpy_s(mmb_name, HIL_MAX_NAME_LEN, buf_local->bufname,
                          (name_len > HIL_MAX_NAME_LEN) ? HIL_MAX_NAME_LEN : name_len)) != EOK) {
                return HI_FAILED;
            }

            addr = hisi_sec_alloc(mmb_name, buf_local->buf_size, buf_local->memtype);
            if (addr != INVIDE_ADDR) {
                if (!(buf_local->memtype)) {
                    buf_local->phys_addr = addr;
                } else {
                    buf_local->smmu_addr = addr;
                }
                res = HI_SUCCESS;
            }
            break;
        case HISI_SEC_MAPTOSMMU:
            addr = hisi_sec_maptosmmu(buf_local->buf_phys, buf_local->buf_size);
            if (addr != INVIDE_ADDR) {
                buf_local->smmu_addr = addr;
                res = HI_SUCCESS;
            }
            break;
        case HISI_SEC_MAPTOSMMU_AND_SETFLAG:
            sec_mmb = hisi_sec_maptosmmu_and_setflag(buf_local->buf_phys, buf_local->buf_size);
            if (sec_mmb != NULL  && sec_mmb->sec_smmu != INVIDE_ADDR) {
                buf_local->smmu_addr = sec_mmb->sec_smmu;
                res = HI_SUCCESS;
            }
            break;
        case CHECK_SEC_SMMU:
            res = is_sec_mem(buf_local->smmu_addr, 1, (bool *)&(buf_local->arg0));
            break;
        case CHECK_SEC_MMZ:
            res = is_sec_mem(buf_local->sec_addr, 0, (bool *)&(buf_local->arg0));
            break;
        default:
            pr_err("The op:(%d) not exist ! \n", op);
            res = HI_FAILED;
    }

    return res;
}

static int hi_smmu_driver_r(int op, struct hi_tee_smmu_ioctl_data *buf_local)
{
    int res = HI_FAILED;

    switch (op) {
        case HISI_SEC_FREE:
            res = hisi_sec_free(buf_local->sec_addr, buf_local->memtype);
            break;
        case HISI_SEC_UNMAPFROMSMMU:
            res = hisi_sec_unmapfromsmmu(buf_local->buf_phys, buf_local->buf_size);
            break;
        case HISI_SEC_UNMAPFROMSMMU_AND_CLRFLG:
            res = hisi_sec_unmapfromsmmu_and_clrflg(buf_local->buf_phys, buf_local->buf_size);
            break;
        case SEC_IOCTL:
            res = sec_ioctl(buf_local->cmd, buf_local->arg0, buf_local->arg1);
            break;
        case CHECK_SEC_SMMU:
            res = is_sec_mem(buf_local->smmu_addr, 1, (bool *)&(buf_local->arg0));
            break;
        case CHECK_SEC_MMZ:
            res = is_sec_mem(buf_local->sec_addr, 0, (bool *)&(buf_local->arg0));
            break;
        default:
            pr_err("The op:(%d) not exist ! \n", op);
            res = HI_FAILED;
    }

    return res;
}

static int copy_data_from_ta_buffer(void *buffer, size_t len, struct hi_tee_smmu_ioctl_data *buf_local)
{
    struct hi_tee_smmu_ioctl_data *buf_para = NULL;
    int check_res;

    if (buffer == NULL || !len) {
        pr_err("The buffer or the len may be NULL !\n");
        return HI_FAILED;
    }

    buf_para = (struct hi_tee_smmu_ioctl_data *)buffer;
    check_res = smmu_access_check((void *)buf_para, len);
    if (check_res != HI_SUCCESS) {
        pr_err("smmu access check failed\n");
        return HI_FAILED;
    }
    check_res = smmu_access_read_right_check((void *)buf_para, len);
    if (check_res != HI_SUCCESS) {
        pr_err("smmu access read right checkfailed\n");
        return HI_FAILED;
    }

    if ((memcpy_s(buf_local, sizeof(struct hi_tee_smmu_ioctl_data),
                  buf_para, sizeof(struct hi_tee_smmu_ioctl_data))) != EOK) {
        pr_err("memcpy_s failed\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int copy_data_to_ta_buffer(void *buffer, size_t len, struct hi_tee_smmu_ioctl_data *buf_local)
{
    struct hi_tee_smmu_ioctl_data *buf_para = NULL;
    int check_res;

    if (buffer == NULL || !len) {
        pr_err("The buffer or the len may be NULL !\n");
        return HI_FAILED;
    }

    buf_para = (struct hi_tee_smmu_ioctl_data *)buffer;
    check_res = smmu_access_write_right_check((void *)buf_para, len);
    if (check_res != HI_SUCCESS) {
        pr_err("smmu access write right check failed\n");
        return HI_FAILED;
    }

    if ((memcpy_s(buf_para, sizeof(struct hi_tee_smmu_ioctl_data),
                  buf_local, sizeof(struct hi_tee_smmu_ioctl_data))) != EOK) {
        pr_err("memcpy_s failed\n");
        return HI_FAILED;
    }

    return HI_SUCCESS;
}

static int hi_smmuagent(unsigned int taskpid, unsigned int suspend)
{
    if (suspend == 1) {
        struct hi_tee_hal_agent_msg msg = {0};
        (void)SRE_MsgSnd(TA_SMMU_AGENT_SUSPEND, taskpid, &msg, sizeof(struct hi_tee_hal_agent_msg));
        hi_tee_drv_set_smmu_agent_msg_info(0);
    } else if (suspend == 0) {
        hi_tee_drv_set_smmu_agent_msg_info(taskpid);
    }

    return HI_SUCCESS;
}

static int hi_smmu_driver(void *buffer, size_t len)
{
    struct hi_tee_smmu_ioctl_data buf_local = {0};
    int flag = 0;
    int ret;

    ret = copy_data_from_ta_buffer(buffer, len, &buf_local);
    if (ret != HI_SUCCESS) {
        pr_err("copy data failed\n");
        return HI_FAILED;
    }

    if (buf_local.cmd_id == AGENT_CLOSED) {
        return agent_closed();
    }

    switch (buf_local.cmd_id) {
        case HISI_SEC_ALLOC:
        case HISI_SEC_MAPTOSMMU:
        case HISI_SEC_MAPTOSMMU_AND_SETFLAG:
            ret = hi_smmu_driver_w(buf_local.cmd_id, &buf_local);
            flag = 1;
            break;
        case CHECK_SEC_SMMU:
        case CHECK_SEC_MMZ:
            flag = 1; /* will enter hi_smmu_driver_r */
        case HISI_SEC_FREE:
        case HISI_SEC_UNMAPFROMSMMU:
        case HISI_SEC_UNMAPFROMSMMU_AND_CLRFLG:
        case SEC_IOCTL:
            ret = hi_smmu_driver_r(buf_local.cmd_id, &buf_local);
            break;
        case HI_SECSMMU_COMMON_AGENT_SUSPEND:
        case HI_SECSMMU_COMMON_AGENT_RESUME:
            return hi_smmuagent(buf_local.arg0, buf_local.arg1);
        default:
            pr_err("The op:(%d) not exist ! \n", buf_local.cmd_id);
            ret = HI_FAILED;
    }

    if (ret == HI_FAILED || flag == 0) {
        return ret;
    }

    ret = copy_data_to_ta_buffer(buffer, len, &buf_local);
    if (ret != HI_SUCCESS) {
        pr_err("copy data failed\n");
        return HI_FAILED;
    }
    return HI_SUCCESS;
}

int hi_smmu_driver_ioctl(int swi_id, struct drv_param *params, uint64_t permissions)
{
    if (params == NULL || params->args == 0)
        return -1;
    uint64_t  *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_SMMU_ID, permissions, GENERAL_GROUP_PERMISSION)
        ACCESS_CHECK(args[0], sizeof(struct hi_tee_smmu_ioctl_data))
        args[0] = hi_smmu_driver((void *)args[0], args[1]);
        SYSCALL_END

    default:
        return -EINVAL;
    }
    return 0;
}

hi_tee_drv_hal_driver_init(smmu_drv, 0, smmu_init, hi_smmu_driver_ioctl, hi_smmu_suspend, hi_smmu_resume);
//hi_tee_drv_hal_service_init_late(smmu_drv, 0, NULL, hi_smmu_driver_ioctl, hi_smmu_suspend, hi_smmu_resume);
