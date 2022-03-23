/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: This file is the file for driver dynamic lib
 * Create: 2021-04
 */

#include "drv_io_share.h"
#include "drv_hwi_share.h"
#include "drv_addr_share.h"
#include "drv_map_share.h"
#include "iomgr_ext.h"
#include "mem_ops_ext.h"
#include <sys/hm_types.h>
#include "drv_thread.h"

void *ioremap(uintptr_t phys_addr, unsigned long size, int32_t prot)
{
    return hm_io_remap((uintptr_t)phys_addr, NULL, size, prot);
}

int32_t iounmap(uintptr_t pddr, const void *addr)
{
    return hm_io_unmap(pddr, addr);
}

uint64_t drv_virt_to_phys(uintptr_t addr)
{
    return __virt_to_phys(addr);
}

uint32_t sys_hwi_create(uint32_t hwi_num, uint16_t hwi_prio, uint16_t mode,
                        HWI_PROC_FUNC handler, uint32_t args)
{
    return SRE_HwiCreate(hwi_num, hwi_prio, mode, handler, args);
}

uint32_t sys_hwi_resume(uint32_t hwi_num, uint16_t hwi_prio, uint16_t mode)
{
    return SRE_HwiResume(hwi_num, hwi_prio, mode);
}

uint32_t sys_hwi_delete(uint32_t hwi_num)
{
    return SRE_HwiDelete(hwi_num);
}

uint32_t sys_hwi_disable(uint32_t hwi_num)
{
    return SRE_HwiDisable(hwi_num);
}

uint32_t sys_hwi_enable(uint32_t hwi_num)
{
    return SRE_HwiEnable(hwi_num);
}

int32_t sys_hwi_notify(uint32_t hwi_num)
{
    return SRE_HwiNotify(hwi_num);
}

static int32_t get_drv_caller_taskid(uint32_t *taskid)
{
    tid_t tid;
    int32_t ret = hm_gettid(&tid);
    if (ret != 0) {
        hm_error("get tid failed\n");
        return -1;
    }

    pid_t caller_pid;
    ret = get_callerpid_by_tid(tid, &caller_pid);
    if (ret != 0) {
        hm_error("get tid:0x%x caller pid failed\n", tid);
        return -1;
    }

    *taskid = (uint32_t)caller_pid;
    return 0;
}

static int32_t tee_map_phy(paddr_t paddr, uint64_t size, uint64_t *vaddr, struct mem_type *mode_type, map_type type)
{
    int32_t ret;
    uint32_t taskid;

    if (vaddr == NULL) {
        hm_error("invalid vaddr\n");
        return -1;
    }

    ret = get_drv_caller_taskid(&taskid);
    if (ret != 0) {
        hm_error("get map caller task id failed\n");
        return -1;
    }

    ret = task_map_phy_mem_type_ex(taskid, paddr, size, vaddr, mode_type, type);
    if (ret != 0) {
        hm_error("map phy failed\n");
        return -1;
    }
    return 0;
}

int32_t tee_map_secure(paddr_t paddr, uint64_t size, uintptr_t *vaddr, cache_mode_type cache_mode)
{
    struct mem_type mode_type;
    uint64_t temp_addr;
    int32_t ret;

    if (vaddr == NULL) {
        hm_error("vaddr is null\n");
        return -1;
    }
    mode_type.secure_mode = secure;
    mode_type.cache_mode = cache_mode;

    ret = tee_map_phy(paddr, size, &temp_addr, &mode_type, MAP_SECURE);
    if (ret != 0) {
        hm_error("tee map secure failed\n");
        return ret;
    }
#ifdef __aarch64__
    *vaddr = temp_addr;
#else
    *vaddr = (uint32_t)temp_addr & 0xFFFFFFFFUL;
#endif
    return 0;
}

int32_t tee_map_nonsecure(paddr_t paddr, uint64_t size, uintptr_t *vaddr, cache_mode_type cache_mode)
{
    struct mem_type mode_type;
    uint64_t temp_addr;
    int32_t ret;

    if (vaddr == NULL) {
        hm_error("vaddr is null\n");
        return -1;
    }

    mode_type.secure_mode = non_secure;
    mode_type.cache_mode = cache_mode;

    ret = tee_map_phy(paddr, size, &temp_addr, &mode_type, MAP_NONSECURE);
    if (ret != 0) {
        hm_error("tee map non-secure failed\n");
        return ret;
    }
#ifdef __aarch64__
    *vaddr = temp_addr;
#else
    *vaddr = (uint32_t)temp_addr & 0xFFFFFFFFUL;
#endif
    return 0;
}
