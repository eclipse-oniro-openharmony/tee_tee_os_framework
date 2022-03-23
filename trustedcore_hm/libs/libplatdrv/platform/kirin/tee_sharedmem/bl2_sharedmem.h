/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: bl2 shared mem declares
 * Create: 2020-04
 */
#ifndef PLATDRV_BL2_SHAREDMEM_H
#define PLATDRV_BL2_SHAREDMEM_H

#include <types.h>

int get_fwdt_shared_mem(uint64_t *addr, uint32_t *size);

#endif
