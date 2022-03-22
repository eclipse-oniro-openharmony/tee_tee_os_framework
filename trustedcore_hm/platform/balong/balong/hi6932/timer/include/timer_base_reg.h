/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: io_map defines
 * Author: chenmou chenmou1@huawei.com
 * Create: 2020-06
 */
#ifndef TIMER_BASE_REG_H
#define TIMER_BASE_REG_H
/* time8 for secure os */
#define TIMER8_BASE      0x2001F000

#define FREE_RUNNING_TIMER_BASE     TIMER8_BASE
#define TICK_TIMER_BASE             TIMER8_BASE

#define FREE_RUNNING_TIMER_NUM 1
#define TICK_TIMER_NUM         0

#define FREE_RUNNING_FIQ_NUMBLER     74
#define TICK_TIMER_FIQ_NUMBLER       73

#endif
