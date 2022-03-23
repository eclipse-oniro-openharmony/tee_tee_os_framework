/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: io_map defines
 * Create: 2020-12-16
 */
#ifndef TIMER_IO_MAP_H
#define TIMER_IO_MAP_H

#include <timer_init.h>
#include <soc_acpu_baseaddr_interface.h>
#include <plat_cfg.h>

struct ioaddr_timer_t g_timer_id_addr[] = {
    /* used in ddr_autofsgt_ctrl() */
    { RTC_BASE_ADDR,               RTC_BASE_ADDR_SIZE,        false },
    { SOC_ACPU_SCTRL_BASE_ADDR,    REG_BASE_SCTRL_SIZE,       false },
    { SOC_ACPU_PERI_CRG_BASE_ADDR, REG_BASE_PERI_CRG_SIZE,    false },
    { SOC_ACPU_PCTRL_BASE_ADDR,    REG_BASE_PCTRL_SIZE,       false },
    { SOC_ACPU_TIMER1_BASE_ADDR,   TIMER1_BASE_SIZE,          false },
    { SOC_ACPU_TIMER7_BASE_ADDR,   TIMER7_BASE_SIZE,          false },
};
#endif
