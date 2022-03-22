/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: record the register mmap information.
 */
#ifndef PLATDRV_IO_MAP_H
#define PLATDRV_IO_MAP_H

#include <plat_cfg.h>
#include <platdrv.h>
#include <mspe_ddr_layout.h>

struct ioaddr_t g_ioaddrs[] = {
    { SOC_ACPU_SCTRL_BASE_ADDR,    REG_BASE_SCTRL_SIZE },
    { SOC_ACPU_PCTRL_BASE_ADDR, REG_BASE_PCTRL_SIZE }, /* PCTRL_BASE */
};

#endif
