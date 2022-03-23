/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: io_map defines
 * Author: hemuyang1@huawei.com
 * Create: 2021-03-09
 */
#ifndef TIMER_IO_MAP_H
#define TIMER_IO_MAP_H

#include <timer_init.h>
#include <timer_reg.h>
#include <plat_cfg.h>

struct ioaddr_timer_t g_timer_id_addr[] = {
    { OS_TIMER0_REG,     OS_TIMER0_REG_SIZE,        false },
    { OS_TIMER1_REG,     OS_TIMER1_REG_SIZE,        false },
    { SUBCTRL_REG,       SUBCTRL_REG_SIZE,          false },
};
#endif
