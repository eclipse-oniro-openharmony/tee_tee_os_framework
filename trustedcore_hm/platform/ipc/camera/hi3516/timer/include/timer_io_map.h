/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: io_map defines
 * Create: 2021-06
 */
#ifndef TIMER_IO_MAP_H
#define TIMER_IO_MAP_H

#include <timer_init.h>
#include <hisi_platform.h>
#include <plat_cfg.h>

struct ioaddr_timer_t g_timer_id_addr[] = {
    /* used in ddr_autofsgt_ctrl() */
    { TIMER1_BASE,       TIMER1_BASE_SIZE,          false },
};
#endif
