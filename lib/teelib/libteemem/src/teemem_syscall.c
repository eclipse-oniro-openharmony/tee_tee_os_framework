/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: syscall functions for teemem
 * Author: liuchunyan liuchunyan9@huawei.com
 * Create: 2018-04-17
 */
#include <hm_mman.h>
#include <sys/mman.h>
#include <mm_kcall.h>
#include <hm/hongmeng.h>
#include <malloc.h>
#include <procmgr.h>
#include <securec.h>
#include <mem_ops.h>
#include <tee_log.h>
#include <hmlog.h>
#include <sys/hmapi.h>
#include <tamgr_ext.h>
#include <ipclib.h>
#include <mem_page_ops.h>
#include <mem_mode.h>
#include <hmdrv.h>
#include <sre_syscalls_id.h>
#include <mem_ops_ext.h>

#define SRE_MAX_NOMAP_MAP_COUNT 19
#define DEFAULT_RIGHT 0

int32_t get_prot_by_secure_cache_mode(secure_mode_type secure_mode, cache_mode_type cache_mode)
{
    int32_t prot = PROT_READ | PROT_WRITE;

    /* set NS flag */
    if (secure_mode == NON_SECURE)
        prot = (uint32_t)prot | PROT_NS;
    if (cache_mode == NON_CACHE)
        prot = (uint32_t)prot | PROT_MA_NC;
    if (cache_mode == CACHE_MODE_DEVICE)
        prot = (uint32_t)prot | PROT_nGnRnE;

    return prot;
}

int32_t task_map_phy_mem_ex(uint32_t task_id, paddr_t phy_addr, uint32_t size,
                                   uint64_t *virt_addr, int32_t prot, map_type type)
{
    uint64_t mapped_addr;

    if (virt_addr == NULL || phy_addr == 0 || size == 0) {
        hm_error("invalid parameters\n");
        return HM_ERROR;
    }

    if (UINT64_MAX - phy_addr < size) {
        hm_error("phy addr plus size overflow\n");
        return HM_ERROR;
    }

    task_id = PID2HMPID(task_id);

    /* map PA to process VA */
    mapped_addr = hm_map_range_to_process((pid_t)task_id, 0, size, prot, phy_addr, (uint32_t)type);
    if (mapped_addr == MAP_FAILED_UINT64) {
        hm_error("hm_map_range failed\n");
        return HM_ERROR;
    }

    /* get value via pointer,hm_map_range_to_process return aligned addr */
    *virt_addr = (uint64_t)(mapped_addr + (phy_addr & PAGE_OFFSET_MASK));
    return HM_OK;
}

int32_t task_map_phy_mem(uint32_t task_id, paddr_t phy_addr, uint32_t size, uint64_t *virt_addr,
                         secure_mode_type secure_mode)
{
    int32_t prot;
    prot = get_prot_by_secure_cache_mode(secure_mode, CACHE);
    return task_map_phy_mem_ex(task_id, phy_addr, size, virt_addr, prot, MAP_ORIGIN);
}

int32_t task_unmap(uint32_t task_id, uint64_t virt_addr, uint32_t size)
{
    if (virt_addr == 0 || size == 0) {
        hm_error("invalid parameters\n");
        return HM_ERROR;
    }

    if (UINT64_MAX - virt_addr < size) {
        hm_error("virt addr plus size overflow\n");
        return HM_ERROR;
    }

    task_id = PID2HMPID(task_id);

    return hm_unmap_range_from_process((pid_t)task_id, virt_addr, size);
}

void *tee_alloc_sharemem_aux(const struct tee_uuid *uuid, uint32_t size)
{
    return hm_alloc_sharemem(uuid, size, 0);
}

void *tee_alloc_coherent_sharemem_aux(const struct tee_uuid *uuid, uint32_t size)
{
    return hm_alloc_sharemem(uuid, size, MAP_COHERENT);
}

uint32_t tee_free_sharemem(void *addr, uint32_t size)
{
    if (addr == NULL || size == 0 || ((size + PAGE_SIZE) < size)) {
        hm_info("invalid parameter size:0x%x\n", size);
        return (uint32_t)HM_ERROR;
    }

    /*
     * unmap a TA2TA region causes force full unmap on server,
     * so we give a minimal size (PAGE_SIZE) here
     */
    size = PAGE_ALIGN_UP(size);
    if (munmap((void *)addr, size)) {
        hm_error("munmap failed, errno = %d\n", errno);
        return (uint32_t)HM_ERROR;
    }

    return HM_OK;
}

static int32_t copy_task_param_check(uint64_t src, uint32_t src_size, uint64_t dst, uint32_t dst_size)
{
    if (src == 0 || dst == 0 || src_size == 0 || dst_size == 0 || src_size > dst_size) {
        tloge("invalid param src size:0x%x dst size:0x%x\n", src_size, dst_size);
        return -1;
    }

    if (src + src_size < src) {
        tloge("invalid src buffer size:0x%x\n", src_size);
        return -1;
    }

    if (dst + dst_size < dst) {
        tloge("invalid dst buffer size:0x%x\n", dst_size);
        return -1;
    }

    return 0;
}

int32_t tee_map_sharemem(uint32_t src_task, uint64_t vaddr, uint64_t size, uint64_t *vaddr_out)
{
    pid_t pid_in = PID2HMPID(src_task);
    return hm_map_sharemem(pid_in, vaddr, size, vaddr_out);
}

int32_t copy_from_sharemem(uint32_t src_task, uint64_t src, uint32_t src_size, uintptr_t dst, uint32_t dst_size)
{
    int32_t ret;
    uint64_t temp_dst;

    ret = copy_task_param_check(src, src_size, dst, dst_size);
    if (ret != 0)
        return -1;

    pid_t pid_in = PID2HMPID(src_task);
    ret = hm_map_sharemem(pid_in, src, src_size, &temp_dst);
    if (ret != 0) {
        tloge("map sharemem failed, src_task:0x%x\n", src_task);
        return -1;
    }

    ret = memcpy_s((void *)dst, dst_size, (void *)(uintptr_t)temp_dst, src_size);
    if (ret != EOK) {
        tloge("copy buffer from sharemem failed\n");
        if (munmap((void *)(uintptr_t)temp_dst, src_size) != 0)
            tloge("unmap temp dst failed in from sharemem\n");
        return -1;
    }

    if (munmap((void *)(uintptr_t)temp_dst, src_size) != 0) {
        tloge("something wrong, unmap temp dst failed in from sharemem\n");
        return -1;
    }

    return 0;
}

int32_t copy_to_sharemem(uintptr_t src, uint32_t src_size, uint32_t dst_task, uint64_t dst, uint32_t dst_size)
{
    int32_t ret;
    uint64_t temp_dst;

    ret = copy_task_param_check(src, src_size, dst, dst_size);
    if (ret != 0)
        return -1;

    pid_t pid_in = PID2HMPID(dst_task);
    ret = hm_map_sharemem(pid_in, dst, dst_size, &temp_dst);
    if (ret != 0) {
        tloge("map sharemem failed, dst_task:0x%x\n", dst_task);
        return -1;
    }

    ret = memcpy_s((void *)(uintptr_t)temp_dst, dst_size, (void *)src, src_size);
    if (ret != EOK) {
        tloge("copy buffer to sharemem failed\n");
        if (munmap((void *)(uintptr_t)temp_dst, dst_size) != 0)
            tloge("unmap temp dst failed in to sharemem\n");
        return -1;
    }

    if (munmap((void *)(uintptr_t)temp_dst, dst_size) != 0) {
        tloge("something wrong, unmap temp dst failed in to sharemem\n");
        return -1;
    }

    return 0;
}


uint64_t tee_virt_to_phys(uintptr_t vaddr)
{
    uint64_t paddr = 0;

    if (virt_to_phys_ex(vaddr, &paddr) < 0) {
        hm_error("tee virt_to_phys failed\n");
        return 0;
    }

    return paddr;
}

