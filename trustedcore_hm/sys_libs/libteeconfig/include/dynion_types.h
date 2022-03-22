/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: copy from teeos, dynamic ion structure shared with gtask and platdrv
 * Create: 2019-11-12
 */
#ifndef LIBTEECONFIG_DYNION_TYPES_H
#define LIBTEECONFIG_DYNION_TYPES_H
#include <sre_typedef.h>

typedef struct ion_page_info {
    paddr_t phys_addr;
    uint32_t npages;
} tz_page_info;

struct ion_sglist {
    UINT64 sglist_size;
    UINT64 ion_size;
    UINT64 ion_id;
    UINT64 info_length; // page_info number
    tz_page_info page_info[0];
};
#endif /* LIBTEECONFIG_DYNION_TYPES_H */
