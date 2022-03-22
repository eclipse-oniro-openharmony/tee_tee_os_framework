/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: io_map defines
 * Author: secureos
 * Create: 2020-06
 */
#ifndef TIMER_BASE_REG_H
#define TIMER_BASE_REG_H
/* time11 for secure os */
#define TIMER_2_0      0xedf19000
#define TIMER_2_1      0xedf19020

#define FREE_RUNNING_TIMER_BASE     TIMER_2_0
#define TICK_TIMER_BASE             TIMER_2_1

#define FREE_RUNNING_TIMER_NUM 0
#define TICK_TIMER_NUM         0

#define FREE_RUNNING_FIQ_NUMBLER     81
#define TICK_TIMER_FIQ_NUMBLER       82
#endif
