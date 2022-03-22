/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: This file is the header file for driver dynamic lib
 * Create: 2021-04
 */
#ifndef LIBDRV_IO_SHARED_H
#define LIBDRV_IO_SHARED_H

#include <stdint.h>

void *ioremap(uintptr_t phys_addr, unsigned long size, int32_t prot);
int32_t iounmap(uintptr_t pddr, const void *addr);

#endif
