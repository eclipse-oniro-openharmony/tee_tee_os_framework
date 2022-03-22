/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: record the register mmap information.
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2021-01
 */
#ifndef PLATDRV_IO_MAP_H
#define PLATDRV_IO_MAP_H

#include <platdrv.h>
#include <plat_cfg.h>

/*
 * for example
 * { ADDR_BASE, ADDR_SIZE }
 * if ADDR_BASE equals zero or ADDR_SIZE equals zero, the address will not be mapped
 */
#define PLATDRV_IO_MAP_OFFSET 0x80000000

struct ioaddr_t g_ioaddrs[] = {
};

#endif
