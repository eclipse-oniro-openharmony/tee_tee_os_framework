/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file about timer
 * Author: hepengfei hepengfei7@huawei.com
 * Create: 2019-08-20
 */
#ifndef DRV_TIMER_PLATFORM_TIMER_KUNPENG_H
#define DRV_TIMER_PLATFORM_TIMER_KUNPENG_H

#include <stdint.h>
#include <timer_types.h>

/*
 * clockcycles * NSECS_PER_MSEC < 2^64
 * so, clockcycles max:
 * 2^64/1000000 (~17 years)
 */
#define FREE_TIMER_COUNT_MAX 18446744073700
#ifdef TIMER_COUNT_MAX
#undef TIMER_COUNT_MAX
#endif

#define TIMER_COUNT_MAX TIMER_COUNT_MAX_64BIT

#define  TIMER_CLK_FREQ 50000000 /* 50M */

#define OS_TIMER0_REG       0x94D00000
#define OS_TIMER1_REG       0x94D10000
#define SUBCTRL_REG         0x94000000

#define FREE_RUNNING_TIMER_BASE     OS_TIMER0_REG
#define TICK_TIMER_BASE             OS_TIMER1_REG


#define FREE_RUNNING_TIMER_NUM 1
#define TICK_TIMER_NUM         0


/* SPI number to call normal world tc_notify_func */
#define SPI_NUM_FOR_NOTIFY 111

/* hi1620 secure timer for totem_b */
#define FREE_RUNNING_FIQ_NUMBLER     152
#define TICK_TIMER_FIQ_NUMBLER       153

#define SC_SECURE_TIMER_CLK_ST  (SUBCTRL_REG + 0x5570)
#define SC_SECURE_TIMER_CLK_EN  (SUBCTRL_REG + 0x570)
#define SC_SECURE_TIMER0_CLK_DIS (SUBCTRL_REG + 0x574)
#define SC_SECURE_TIMER_CLK_SEL (SUBCTRL_REG + 0x3130)

#define SECURE_TIMER_CLK_EN_VALUE 0x11
#define SECURE_TIMER_CLK_50M 0xFFFFFFF0


#define TIMER64_LOAD_L_REG0     (OS_TIMER0_REG + 0x0000)
#define TIMER64_LOAD_L_REG1     (OS_TIMER1_REG + 0x0000)
#define TIMER64_LOAD_H_REG0     (OS_TIMER0_REG + 0x0004)
#define TIMER64_LOAD_H_REG1     (OS_TIMER1_REG + 0x0004)
#define TIMER64_CONTROL_REG0    (OS_TIMER0_REG + 0x0010)
#define TIMER64_CONTROL_REG1    (OS_TIMER1_REG + 0x0010)
#define TIMER64_VALUE_L_REG0    (OS_TIMER0_REG + 0x0020)
#define TIMER64_VALUE_L_REG1    (OS_TIMER1_REG + 0x0020)
#define TIMER64_VALUE_H_REG0    (OS_TIMER0_REG + 0x0024)
#define TIMER64_VALUE_H_REG1    (OS_TIMER1_REG + 0x0024)
#define TIMER64_INTCLR_REG0     (OS_TIMER0_REG + 0x0014)
#define TIMER64_INTCLR_REG1     (OS_TIMER1_REG + 0x0014)
#define TIMER64_MIS_REG0        (OS_TIMER0_REG + 0x001C)
#define TIMER64_MIS_REG1        (OS_TIMER1_REG + 0x001C)
#define TIMER64_RIS_REG0        (OS_TIMER0_REG + 0x0018)
#define TIMER64_RIS_REG1        (OS_TIMER1_REG + 0x0018)
#define TIMER64_BGLOAD_L_REG0   (OS_TIMER0_REG + 0x0008)
#define TIMER64_BGLOAD_L_REG1   (OS_TIMER1_REG + 0x0008)
#define TIMER64_BGLOAD_H_REG0   (OS_TIMER0_REG + 0x000C)
#define TIMER64_BGLOAD_H_REG1   (OS_TIMER1_REG + 0x000C)

#endif
