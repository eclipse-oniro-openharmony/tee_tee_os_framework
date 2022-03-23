/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: io_map defines
 * Create: 2020-03
 */
#ifndef TIMER_IO_MAP_H
#define TIMER_IO_MAP_H

#include <timer_init.h>
#include <hisi_platform.h>
#include <plat_cfg.h>

struct ioaddr_timer_t g_timer_id_addr[] = {
    /* used in ddr_autofsgt_ctrl() */
    { RTC_BASE_ADDR,     RTC_BASE_ADDR_SIZE,        false },
    { REG_BASE_SCTRL,    REG_BASE_SCTRL_SIZE,       false },
    { REG_BASE_PERI_CRG, REG_BASE_PERI_CRG_SIZE,    false },
    { REG_BASE_PCTRL,    REG_BASE_PCTRL_SIZE,       false },
    { TIMER1_BASE,       TIMER1_BASE_SIZE,          false },
    { TIMER7_BASE,       TIMER7_BASE_SIZE,          false },
};
#endif
