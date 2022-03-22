/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: record the register mmap information.
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-03
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
struct ioaddr_t g_ioaddrs[] = {
    {HI_ES_TSP_REG_BASE, HI_ES_TSP_REG_SIZE},
    {HI_SYSCTRL_BASE_ADDR, HI_SYSCTRL_BASE_ADDR_SIZE},
    {HI_NR_SYSCTRL_BASE_ADDR, HI_NR_SYSCTRL_BASE_SIZE},
    {DX_BASE_CC, DX_BASE_CC_SIZE},
    {HI_EFUSE_SYSCTRL_BASE_ADDR, HI_EFUSE_SYSCTRL_BASE_SIZE},
    {HI_IPCM_REGBASE_ADDR, HI_IPCM_REGBASE_ADDR_SIZE},
    {REG_BASE_SCTRL, REG_BASE_SCTRL_SIZE},
    {EICC_PERI_REGBASE_VADDR, EICC_REGBASE_SIZE},
    {EICC_MDM0_REGBASE_VADDR, EICC_REGBASE_SIZE},
};

#endif
