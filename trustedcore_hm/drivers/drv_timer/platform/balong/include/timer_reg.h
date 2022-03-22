/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file about timer
 * Author: hepengfei hepengfei7@huawei.com
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_PLATFORM_TIMER_H
#define DRV_TIMER_PLATFORM_TIMER_H

#include <stdint.h>
#include <timer_base_reg.h>
#include <timer_types.h>

#ifdef TIMER_COUNT_MAX
#undef TIMER_COUNT_MAX
#endif

#define TIMER_CLK_FREQ          32768
#define TIMER_COUNT_MAX TIMER_COUNT_MAX_32BIT
#define TIMER_LOAD  0x00
#define TIMER_VALUE 0x04
#define TIMER_CTRL  0x08

#define TIMER_CTRL_ONESHOT  (1U << 0)
#define TIMER_CTRL_32BIT    (1U << 1)
/* Interrupt Enable (versatile only) */
#define TIMER_CTRL_IE       (1U << 5)
#define TIMER_CTRL_PERIODIC (1U << 6)
#define TIMER_CTRL_ENABLE   (1U << 7)

#define TIMER_INTCLR 0x0c
#define TIMER_MIS    0x14

#endif /* DRV_TIMER_PLATFORM_TIMER_H */
