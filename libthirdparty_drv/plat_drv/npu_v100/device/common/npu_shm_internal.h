/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu sec mem map and unmap
 */
#ifndef __NPU_SHM_INTERNAL_H
#define __NPU_SHM_INTERNAL_H
#include "mem_page_ops.h"

uint32_t npu_sec_mem_map(paddr_t paddr, uint32_t size, uint32_t *vaddr, uint32_t secure_mode, uint32_t cache_mode);

uint32_t npu_sec_mem_unmap(uint32_t vaddr, uint32_t size);

#endif
