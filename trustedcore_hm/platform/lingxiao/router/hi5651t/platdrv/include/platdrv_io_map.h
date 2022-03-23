/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: record the register mmap information.
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-03
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
    { SEC_KDF0_BASE, SEC_KDF0_SIZE },
    { SEC_PKE_BASE, SEC_PKE_SIZE },
    { SEC_SEC0_BASE, SEC_SEC0_SIZE },
    { HI_SEC_REG_CRG_DIO_BASE, HI_SEC_REG_CRG_DIO_SIZE },
};

#endif
