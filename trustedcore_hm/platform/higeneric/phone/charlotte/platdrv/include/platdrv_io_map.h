/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: record the register mmap information.
 * Create: 2020-12-08
 */
#ifndef PLATDRV_IO_MAP_H
#define PLATDRV_IO_MAP_H

#include <plat_cfg.h>
#include <platdrv.h>

struct ioaddr_t g_ioaddrs[] = {
    { SOC_ACPU_SCTRL_BASE_ADDR, REG_BASE_SCTRL_SIZE },
    { SOC_ACPU_PERI_CRG_BASE_ADDR, REG_BASE_PERI_CRG_SIZE },
    { SOC_ACPU_PCTRL_BASE_ADDR, REG_BASE_PCTRL_SIZE },
    { SOC_ACPU_IPC_BASE_ADDR, SOC_ACPU_IPC_BASE_ADDR_SIZE },
};

#endif
