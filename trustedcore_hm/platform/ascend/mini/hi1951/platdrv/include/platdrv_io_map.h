/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: record the register mmap information.
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-03
 */
#ifndef PLATDRV_IO_MAP_H
#define PLATDRV_IO_MAP_H

#include <plat_cfg.h>
#include <platdrv.h>

/*
 * for example
 * { ADDR_BASE, ADDR_SIZE }
 * if ADDR_BASE equals zero or ADDR_SIZE equals zero, the address will not be mapped
 */
struct ioaddr_t g_ioaddrs[] = {
    {SEC_BASE_ADDR, SEC_BASE_SIZE},
    {PEH_PF_REGS_BASE_ADDR, PEH_BASE_SIZE},
    {SC_SEC_PBU_REGS_BASE_ADDR, PBU_BASE_SIZE},
    {HAC_SUBCTRL_REG_ADDR, HAC_SUBSCTRL_BASE_SIZE},
    {CFG_DISP_BASE_ADDR, CFG_DISP_SIZE},
    {TRNG_BASE_ADDR, TRNG_BASE_SIZE},
    {SCMI0_REG_BASE, SCMI0_REG_ADDR_SIZE}, /* scmi driver */
    {SCMI0_REG_BASE_P1, SCMI0_REG_ADDR_SIZE}, /* P1 scmi driver */
    {SFC0_REG_BASE_ADDR, SFC_REG_SIZE}, /* sfc driver */
    {SFC1_REG_BASE_ADDR, SFC_REG_SIZE}, /* sfc1 driver */
    {SFC0_FLASH_MEM_BASE_ADDR, SFC_FLASH_MEM_SIZE},
    {SFC1_FLASH_MEM_BASE_ADDR, SFC_FLASH_MEM_SIZE },
    {SYSCTRL_REG_BASE, SYSCTRL_REG_SIZE},
    {SYSCTRL1_REG_BASE, SYSCTRL1_REG_SIZE},
    {EFUSE0_CTRL_BASE, EFUSE0_CTRL_SIZE},
    {EFUSE0_CTRL_P1_BASE, EFUSE0_CTRL_SIZE},
    {EFUSE1_CTRL_BASE, EFUSE1_CTRL_SIZE},
    {EFUSE1_CTRL_P1_BASE, EFUSE1_CTRL_SIZE},
    {SRAM0_CTRL_BASE_ADDR, SRAM_CTRL_SIZE},
    {SRAM1_CTRL_BASE_ADDR, SRAM_CTRL_SIZE},
};

#endif
