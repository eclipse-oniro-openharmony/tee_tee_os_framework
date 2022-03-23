/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: io_map defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-03
 */
#ifndef TIMER_IO_MAP_H
#define TIMER_IO_MAP_H

#include <timer_init.h>
#include <plat_cfg.h>

struct ioaddr_timer_t g_timer_id_addr[] = {
    { RTC_BASE_ADDR,     RTC_BASE_ADDR_SIZE,        false },
    { REG_BASE_SCTRL,    REG_BASE_SCTRL_SIZE,       false },
    { TIMER6_BASE,       TIMER6_BASE_SIZE,          false },
};
#endif
