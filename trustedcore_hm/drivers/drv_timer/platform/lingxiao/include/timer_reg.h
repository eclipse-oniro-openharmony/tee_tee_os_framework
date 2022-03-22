/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Header file about timer
 * Author: lilianhui lilianhui1@huawei.com
 * Create: 2020-04-27
 */

#ifndef DRV_TIMER_PLATFORM_TIMER_LINGXIAO_H
#define DRV_TIMER_PLATFORM_TIMER_LINGXIAO_H
#include <timer_types.h>

#define TIMER_CLK_FREQ          32768
#define TICK_TIMER_FIQ_NUMBLER  94
#ifdef TIMER_COUNT_MAX
#undef TIMER_COUNT_MAX
#endif
#define TIMER_COUNT_MAX TIMER_COUNT_MAX_32BIT
#endif /* DRV_TIMER_PLATFORM_TIMER_LINGXIAO_H */
