/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: record the register mmap information.
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-03
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
    {SEC_PBU_REGS_BASE_ADDR, PBU_BASE_SIZE},
    {PEH_PF_REGS_BASE_ADDR, PEH_BASE_SIZE},
    {HAC_SUBCTRL_REG_ADDR, HAC_SUBSCTRL_BASE_SIZE},
    {SEC_BASE, SEC_BASE_SIZE},
};
#endif
