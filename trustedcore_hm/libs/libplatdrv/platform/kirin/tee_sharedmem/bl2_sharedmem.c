/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: bl2 shared mem implementations
 * Create: 2020-04
 */
#include "bl2_sharedmem.h"

#include <plat_cfg.h>
#include "sre_log.h"
#include "global_ddr_map.h"

#define TEEOS_SHAREDMEM_BASE_ADDR       (HISI_RESERVED_SECOS_PHYMEM_BASE + SHMEM_OFFSET)

#define TEEOS_SHAREDMEM_FWDTB_SIZE  0x1000

int32_t get_fwdt_shared_mem(uint64_t *addr, uint32_t *size)
{
    if ((addr == NULL) || (size == NULL)) {
        tloge("params error\n");
        return 1;
    }

    *addr = TEEOS_SHAREDMEM_BASE_ADDR + TEEOS_SHAREDMEM_FWDTB_SIZE;
    *size = TEEOS_SHAREDMEM_FWDTB_SIZE;

    return 0;
}
