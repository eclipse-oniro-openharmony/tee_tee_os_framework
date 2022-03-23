/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: record the register mmap information.
 * Author: hemuyang1@huawei.com
 * Create: 2021-03-09
 */
#ifndef PLATDRV_IO_MAP_HI1620_H
#define PLATDRV_IO_MAP_HI1620_H

#include <platdrv.h>
#include <plat_cfg.h>

/*
 * for example
 * { ADDR_BASE, ADDR_SIZE }
 * if ADDR_BASE equals zero or ADDR_SIZE equals zero, the address will not be mapped
 */
struct ioaddr_t g_ioaddrs[] = {
    {TRNG_BASE_ADDR_CHIP0, TRNG_ADDR_SIZE_CHIP0},
};
#endif
