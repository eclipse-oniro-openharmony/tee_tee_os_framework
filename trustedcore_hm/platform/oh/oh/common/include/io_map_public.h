/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: record the register mmap information.
 * Create: 2022-01-04
 */
#ifndef PLATDRV_IO_MAP_PUBLIC_H
#define PLATDRV_IO_MAP_PUBLIC_H

#include <platdrv.h>

/*
 * for example
 * { ADDR_BASE, ADDR_SIZE }
 * if ADDR_BASE equals zero or ADDR_SIZE equals zero, the address will not be mapped
 */
struct ioaddr_t g_ioaddrs_public[] = {
    { 0, 0 },
};

#endif
