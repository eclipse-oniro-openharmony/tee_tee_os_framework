/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: secos get dt hander
 * Create: 2020-04-30
 */
#include "tee_log.h"

#include "boot_sharedmem.h"
#include "hm_mman_ext.h"
#include "fdt_handler.h"

#define TEEOS_SHAREDMEM_OFFSET_FWDTB    0x1000
#define TEEOS_SHAREDMEM_FWDTB_SIZE      0x1000

uintptr_t get_fwdt_handler()
{
    int ret;
    uintptr_t sharedmem_vaddr = 0;
    bool sharedmem_flag = false;
    uint32_t sharedmem_size;

    if (get_sharedmem_addr(&sharedmem_vaddr,
                           &sharedmem_flag, &sharedmem_size) != 0) {
        tloge("get sharedmem paras failed\n");
        return 0;
    }

    if (sharedmem_vaddr == 0 || !sharedmem_flag) {
        tloge("sharedmem init failed\n");
        return 0;
    }

    if (sharedmem_size < (TEEOS_SHAREDMEM_OFFSET_FWDTB + TEEOS_SHAREDMEM_FWDTB_SIZE)) {
        tloge("sharedmem_size error: 0x%x\n", sharedmem_size);
        return 0;
    }

    return (uintptr_t)((uint64_t)sharedmem_vaddr + TEEOS_SHAREDMEM_OFFSET_FWDTB);
}
