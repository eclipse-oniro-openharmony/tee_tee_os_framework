/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: moved from teeos, dynamic ION memory structure
 * Create: 2019-11-08
 */
#ifndef PLATDRV_DYNION_H
#define PLATDRV_DYNION_H
#include <sre_typedef.h>
#include <stdint.h>
#include "mem_page_ops.h"

typedef struct tz_pageinfo {
    paddr_t phys_addr;
    uint32_t npages;
} TEE_PAGEINFO;

struct sglist {
    /*
     * total sglist size,include info array.
     * size is (sizeof(TEE_PAGEINFO)*infoLength + sizeof(totalSize) + sizeof(infoLength))
     */
    uint64_t sglistSize;
    uint64_t ion_size; /* ca alloced ion size */
    uint64_t ion_id;
    uint64_t infoLength; /* info array size */
    TEE_PAGEINFO info[0];
};
#endif /* PLATDRV_DYNION_H */
