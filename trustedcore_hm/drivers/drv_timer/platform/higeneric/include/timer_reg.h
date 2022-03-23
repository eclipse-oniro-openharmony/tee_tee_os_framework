/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file about timer
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_PLATFORM_TIMER_H
#define DRV_TIMER_PLATFORM_TIMER_H

#include <stdint.h>
#include <timer_types.h>
#include "soc_acpu_baseaddr_interface.h"

#define TIMER_CLK_FREQ 32768
#ifndef TIMER_COUNT_MAX
#define TIMER_COUNT_MAX TIMER_COUNT_MAX_32BIT
#endif
#define TIMER1_BASE SOC_ACPU_TIMER1_BASE_ADDR
#define TIMER7_BASE SOC_ACPU_TIMER7_BASE_ADDR

#define FREE_RUNNING_TIMER_BASE     TIMER1_BASE
#define TICK_TIMER_BASE             TIMER7_BASE

#define FREE_RUNNING_TIMER_NUM 1
#define TICK_TIMER_NUM         0

#ifdef HI_TIMER_V500_EX_FIQ_NUM
/* timer11 */
#define FREE_RUNNING_FIQ_NUMBLER     97
/* timer70 */
#define TICK_TIMER_FIQ_NUMBLER       101
/* Secure RTC1 */
#define SECURE_RTC_FIQ_NUMBLER       89
#else
/* timer11 */
#define FREE_RUNNING_FIQ_NUMBLER     83
/* timer70 */
#define TICK_TIMER_FIQ_NUMBLER       94
/* Secure RTC1 */
#define SECURE_RTC_FIQ_NUMBLER       79
#endif
/* NMI watchdog */
#define WDT_FIQ_NUMBLER              76
/* NMI watchdog */
#define SGI_DUMP_NUMBLER             0xB

/* secure timer force high */
#define SECURE_TIMER_FORCE_HIGH (1U << 31)

#define SCCTRL_TIMEREN0SEL_TIMCLK  (1 << 9)
#define SCCTRL_TIMEREN1SEL_TIMCLK  (1 << 11)
#define SCCTRL_TIMEREN2SEL_TIMCLK  (1 << 13)
#define SCCTRL_TIMEREN3SEL_TIMCLK  (1 << 15)
#define SCCTRL_TIMEREN4SEL_TIMCLK  (1 << 17)
#define SCCTRL_TIMEREN5SEL_TIMCLK  (1 << 19)
#define SCCTRL_TIMEREN6SEL_TIMCLK  (1 << 21)
#define SCCTRL_TIMEREN7SEL_TIMCLK  (1 << 23)
#define PTCRL_TIMEEREN8SEL_TIMCLK  (1 << 0)
#define PTCRL_TIMEEREN9SEL_TIMCLK  (1 << 2)
#define PTCRL_TIMEEREN10SEL_TIMCLK (1 << 4)
#define PTCRL_TIMEEREN11SEL_TIMCLK (1 << 6)
#define PTCRL_TIMEEREN12SEL_TIMCLK (1 << 8)
#define PTCRL_TIMEEREN13SEL_TIMCLK (1 << 10)
#define PTCRL_TIMEEREN14SEL_TIMCLK (1 << 12)
#define PTCRL_TIMEEREN15SEL_TIMCLK (1 << 14)

#ifdef HI_TIMER_V500
#define TIMER_CLK_CTRL 0x0
#define TIMER_LOAD     0x04
#define TIMER_CTRL     0x08
#define TIMER_VALUE    0x14

#define TIMER_CTRL_ENABLE   (1U << 0)
#define TIMER_CTRL_32BIT    (1U << 1)
#define TIMER_CTRL_ONESHOT  (1U << 2)
/* Interrupt Enable (versatile only) */
#define TIMER_CTRL_PERIODIC (1U << 3)
#define TIMER_CTRL_IE       (1U << 4)

#define TIMER_GT_CLK_TIMER1  (1U << 1)
#define TIMER_GT_PCLK_TIMER1 (1U << 0)

#define TIMER_GT_PCLK_TIMER7 (1U << 16)
#define TIMER_GT_CLK_TIMER7  (1U << 17)

#define TIMER_MIS    0x0c
#define TIMER_INTCLR 0x10
#else
#define TIMER_LOAD  0x00
#define TIMER_VALUE 0x04
#define TIMER_CTRL  0x08

#define TIMER_CTRL_ONESHOT  (1U << 0)
#define TIMER_CTRL_32BIT    (1U << 1)
#define TIMER_CTRL_DIV1     (0U << 2)
#define TIMER_CTRL_DIV16    (1U << 2)
#define TIMER_CRTL_RESERVED (1U << 3)
#define TIMER_CTRL_DIV256   (2U << 2)
/* Interrupt Enable (versatile only) */
#define TIMER_CTRL_IE       (1U << 5)
#define TIMER_CTRL_PERIODIC (1U << 6)
#define TIMER_CTRL_ENABLE   (1U << 7)

#define TIMER_GT_CLK_TIMER1  (1U << 1)
#define TIMER_GT_PCLK_TIMER1 (1U << 0)
#define TIMER_GT_PCLK_TIMER6 (1U << 14)

#define TIMER_GT_PCLK_TIMER7 (1U << 16)
#define TIMER_GT_CLK_TIMER7  (1U << 17)
#define TIMER_EN_FORCE_HIGH  (1U << 0)

#define TIMER_INTCLR 0x0c
#define TIMER_RIS    0x10
#define TIMER_MIS    0x14
#define TIMER_BGLOAD 0x18
#endif

#endif
