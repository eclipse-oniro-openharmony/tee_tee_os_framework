/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Header file about timer
 * Create: 2020-07
 */

#ifndef DRV_TIMER_PLATFORM_TIMER_REG_H
#define DRV_TIMER_PLATFORM_TIMER_REG_H

#include <stdint.h>
#include <timer_types.h>

#define TIMER_CLK_FREQ 3000000

#ifdef TIMER_COUNT_MAX
#undef TIMER_COUNT_MAX
#endif

#define TIMER_COUNT_MAX TIMER_COUNT_MAX_32BIT

#define TIMER0_BASE 0x12000000

#define FREE_RUNNING_TIMER_BASE     TIMER0_BASE
#define TICK_TIMER_BASE             TIMER0_BASE

#define FREE_RUNNING_TIMER_NUM 1
#define TICK_TIMER_NUM         0

#define FREE_RUNNING_FIQ_NUMBLER     33
#define TICK_TIMER_FIQ_NUMBLER       33

#define TIMER_LOAD   0x00
#define TIMER_VALUE  0x04
#define TIMER_CTRL   0x08
#define TIMER_INTCLR 0x0c
#define TIMER_RIS    0x10
#define TIMER_MIS    0x14
#define TIMER_BGLOAD 0x18

#define TIMER_CTRL_ONESHOT  (1U << 0)
#define TIMER_CTRL_16BIT    (0U << 1)
#define TIMER_CTRL_32BIT    (1U << 1)
#define TIMER_CTRL_DIV1     (0U << 2)
#define TIMER_CTRL_DIV16    (1U << 2)
#define TIMER_CTRL_DIV256   (2U << 2)
/* Interrupt Enable (versatile only) */
#define TIMER_CTRL_IE       (1U << 5)
#define TIMER_CTRL_PERIODIC (1U << 6)
#define TIMER_CTRL_ENABLE   (1U << 7)

#endif
