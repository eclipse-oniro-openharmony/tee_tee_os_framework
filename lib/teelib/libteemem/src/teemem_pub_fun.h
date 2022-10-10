/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: teemem public func Interface
 * Create: 2022-04-20
 */

#ifndef IBTEEMEM_TEEMEM_PUB_FUN_H
#define IBTEEMEM_TEEMEM_PUB_FUN_H
#include <mem_mode.h>
int32_t get_prot_by_secure_cache_mode(secure_mode_type secure_mode, cache_mode_type cache_mode);

int32_t task_map_phy_mem_ex(uint32_t task_id, paddr_t phy_addr, uint32_t size,
                                   uint64_t *virt_addr, int32_t prot, map_type type);

#define GET_LOW_32BIT(x) ((uint64_t)0x00000000ffffffff & (x))
#endif