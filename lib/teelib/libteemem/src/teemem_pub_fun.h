/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef IBTEEMEM_TEEMEM_PUB_FUN_H
#define IBTEEMEM_TEEMEM_PUB_FUN_H
#include <mem_mode.h>
int32_t get_prot_by_secure_cache_mode(secure_mode_type secure_mode, cache_mode_type cache_mode);

int32_t task_map_phy_mem_ex(uint32_t task_id, paddr_t phy_addr, uint32_t size,
                                   uint64_t *virt_addr, int32_t prot, map_type type);

#define GET_LOW_32BIT(x) ((uint64_t)0x00000000ffffffff & (x))
#endif