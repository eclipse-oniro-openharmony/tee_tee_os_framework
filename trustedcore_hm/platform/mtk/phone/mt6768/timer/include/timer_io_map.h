/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: io_map defines
 * Author: wangcong  wangcong48@huawei.com
 * Create: 2020-07-28
 */
#ifndef TIMER_IO_MAP_H
#define TIMER_IO_MAP_H

#include "plat_cfg.h"

struct ioaddr_timer_t g_timer_id_addr[] = {
    { TIMER1_BASE, TIMER1_BASE_SIZE, false },
    { RTC_BASE_ADDR, RTC_BASE_ADDR_SIZE, false },
};
#endif
