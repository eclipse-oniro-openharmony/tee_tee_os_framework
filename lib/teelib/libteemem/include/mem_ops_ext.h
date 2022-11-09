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
#ifndef MEM_OPS_EXT_H
#define MEM_OPS_EXT_H
#include <stdint.h>
#include <mem_page_ops.h> /* paddr_t */
#include <mem_mode.h> /* secure_mode_type */
#include <tee_defines.h>
#include "tee_sharemem_ops.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */

/* map non_secure memory to TEE, return address is 64bit */
int32_t task_map_phy_mem(uint32_t task_id, paddr_t phy_addr, uint32_t size,
                         uint64_t *virt_addr, secure_mode_type non_secure);

/* unmap memory from task_id, input address is 64bit */
int32_t task_unmap(uint32_t task_id, uint64_t va_addr, uint32_t size);

/* get physicall address of input virtual address, with policy permission check */
uint64_t tee_virt_to_phys(uintptr_t addr);

int32_t tee_map_sharemem(uint32_t src_task, uint64_t vaddr, uint64_t size, uint64_t *vaddr_out);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif /* MEM_OPS_EXT_H */
