/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: This file is the file for driver dynamic lib
 * Create: 2021-04
 */

#include "drv_io_share.h"
#include "drv_addr_share.h"
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
    return tee_virt_to_phys(addr);
}
