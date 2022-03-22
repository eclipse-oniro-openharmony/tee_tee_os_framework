/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: This file is the header file for driver dynamic lib
 * Create: 2021-04
 */
#ifndef LIBDRV_ADDR_SHARED_H
#define LIBDRV_ADDR_SHARED_H

#include <stdint.h>

uint64_t drv_virt_to_phys(uintptr_t addr);

#endif