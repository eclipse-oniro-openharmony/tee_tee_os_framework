/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: record the register mmap information.
 * Create: 2022-01-04
 */
#ifndef PLATDRV_IO_MAP_H
#define PLATDRV_IO_MAP_H

#include <platdrv.h>
#include "plat_cfg.h"

/*
 * for example
 * { ADDR_BASE, ADDR_SIZE }
 * if ADDR_BASE equals zero or ADDR_SIZE equals zero, the address will not be mapped
 */
struct ioaddr_t g_ioaddrs[] = {
    { SEC_TRNG0_BASE, SEC_TRNG0_SIZE },
    { SEC_CLK_BASE, SEC_CLK_SIZE },
    { SEC_KLAD_BASE, SEC_KLAD_SIZE },
    { SEC_OTP_BASE, SEC_OTP_SIZE },
};

#endif
