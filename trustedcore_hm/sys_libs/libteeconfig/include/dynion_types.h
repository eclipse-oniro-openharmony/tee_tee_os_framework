/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: copy from teeos, dynamic ion structure shared with gtask and platdrv
 * Create: 2019-11-12
 */
#ifndef LIBTEECONFIG_DYNION_TYPES_H
#define LIBTEECONFIG_DYNION_TYPES_H
#include <stdint.h>

typedef struct ion_page_info {
    uint64_t phys_addr;
    uint32_t npages;
} tz_page_info;

struct ion_sglist {
    uint64_t sglist_size;
    uint64_t ion_size;
    uint64_t ion_id;
    uint64_t info_length; // page_info number
    tz_page_info page_info[0];
};
#endif /* LIBTEECONFIG_DYNION_TYPES_H */
