/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: drv_map functions for teemem
 * Author: luozhengyi luozhengyi@huawei.com
 * Create: 2022-04-20
 */
#include <procmgr.h>
#include <hmlog.h>
#include <ipclib.h>
#include <mem_ops.h>
#include <mem_ops_ext.h>
#include <hm_mman_ext.h>
#include <sys/hmapi.h>
#include <teecall_cap.h>
#include <sre_syscalls_id.h>
#include <hmdrv.h>
#include <boot_sharedmem.h>
#include "teemem_pub_fun.h"

int32_t task_map_phy_mem_type(uint32_t task_id, paddr_t phy_addr, uint32_t size, uint64_t *virt_addr,
                              struct mem_type *mode_type)
{
    int32_t prot;

    if (mode_type == NULL) {
        hm_error("map phy mem type invalid\n");
        return HM_ERROR;
    }

    prot = get_prot_by_secure_cache_mode(mode_type->secure_mode, mode_type->cache_mode);
    return task_map_phy_mem_ex(task_id, phy_addr, size, virt_addr, prot, MAP_ORIGIN);
}

int32_t task_map_from_ns_page_ex(uint32_t task_id, paddr_t phy_addr, uint32_t size, uint32_t *virt_addr,
                                 struct mem_type memory_type)
{
    uint64_t mapped_addr;
    int32_t prot;

    if (virt_addr == NULL) {
        hm_error("invalid virt_addr\n");
        return HM_ERROR;
    }

    prot = get_prot_by_secure_cache_mode(memory_type.secure_mode, memory_type.cache_mode);
    if (task_map_phy_mem_ex(task_id, phy_addr, size, &mapped_addr, prot, MAP_ORIGIN) != HM_OK) {
        hm_error("map failed\n");
        return HM_ERROR;
    }

    *virt_addr = (uint32_t)GET_LOW_32BIT(mapped_addr);
    return HM_OK;
}

uint64_t __virt_to_phys(uintptr_t vaddr)
{
    uint64_t paddr = 0;

    /* ensure teecall cap granted */
    int32_t err = req_grant();
    if (err < 0)
        return err;

    err = hmex_teecall_cap_vptr_to_paddr(CREF_NULL, vaddr, 1, &paddr);
    if (err < 0) {
        hm_error("virt_to_phys failed\n");
        return 0;
    }

    return paddr;
}

paddr_t virt_mem_to_phys(uintptr_t v_addr)
{
    return __virt_to_phys(v_addr);
}
