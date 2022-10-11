/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: This file is the header file for driver dynamic lib
 * Create: 2021-12
 */
#ifndef LIBDRV_MAP_SHARED_H
#define LIBDRV_MAP_SHARED_H

#include <stdint.h>
#include "mem_ops.h"

int32_t tee_map_secure(paddr_t paddr, uint64_t size, uintptr_t *vaddr, cache_mode_type cache_mode);
int32_t tee_map_nonsecure(paddr_t paddr, uint64_t size, uintptr_t *vaddr, cache_mode_type cache_mode);

#endif
