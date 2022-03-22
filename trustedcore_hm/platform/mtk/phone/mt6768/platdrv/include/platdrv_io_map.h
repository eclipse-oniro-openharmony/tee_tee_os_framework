/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: record the register mmap information.
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-07-28
 */
#ifndef PLATDRV_IO_MAP_H
#define PLATDRV_IO_MAP_H

#include <plat_cfg.h>
#include <platdrv.h>

struct ioaddr_t g_ioaddrs[] = {
    { SPI0_BASE_ADDR, SPI0_BASE_SIZE },
    { SPI5_BASE_ADDR, SPI5_BASE_SIZE },
    { GPIO_BASE_ADDR, GPIO_BASE_SIAE },
};

#endif
