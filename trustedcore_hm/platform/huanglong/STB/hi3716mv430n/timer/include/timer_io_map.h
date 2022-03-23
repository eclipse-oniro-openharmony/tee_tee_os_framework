/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: io_map defines
 * Create: 2020-03
 */
#ifndef TIMER_IO_MAP_H
#define TIMER_IO_MAP_H

#include <plat_cfg.h>
struct ioaddr_timer_t g_timer_id_addr[] = {
    { TIMER1_BASE_PADDR,       TIMER1_BASE_SIZE,          false },
    { TIMER7_BASE_PADDR,       TIMER7_BASE_SIZE,          false },
};
#endif
