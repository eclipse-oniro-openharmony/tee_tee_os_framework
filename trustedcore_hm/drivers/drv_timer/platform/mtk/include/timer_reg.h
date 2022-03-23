/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Header file about timer
 * Author: hepengfei hepengfei7@huawei.com
 * Create: 2020-04-05
 */

#ifndef DRV_TIMER_PLATFORM_MTK_TIMER_REG_H
#define DRV_TIMER_PLATFORM_MTK_TIMER_REG_H

#include <stdint.h>
#include <timer_types.h>
#include <timer_base_reg.h>

/*
 * clockcycles * NSECS_PER_MSEC < 2^64
 * so, clockcycles max:
 *             2^64/1000000 (~17 years)
 */
#ifdef TIMER_COUNT_MAX
#undef TIMER_COUNT_MAX
#endif
#define FREE_TIMER_COUNT_MAX 18446744073700
#define TIMER_COUNT_MAX TIMER_COUNT_MAX_64BIT
#define TIMER_CLK_FREQ 32768

#define TIMER1_BASE 0x1000A000

#define TICK_TIMER_BASE               (TIMER1_BASE + 0x210)
#define FREE_RUNNING_TIMER_BASE       (TIMER1_BASE + 0x220 - 0x20)
#define FREE_RUNNING_TIMER_BASE_TIMEL (TIMER1_BASE + 0x220 - 0x20)
#define FREE_RUNNING_TIMER_BASE_TIMEH (TIMER1_BASE + 0x220 - 0x20 + 0x4)

#define FREE_RUNNING_TIMER_NUM 1
#define TICK_TIMER_NUM         0

#define TIMER_VALUE 0x08

#define SGPT_BASE           0x1000A200
#define SGPT_IRQEN          ((uint32_t *)(SGPT_BASE))
#define SGPT_IRQSTATUS      ((uint32_t *)(SGPT_BASE + 0x04))
#define SGPT_IRQACK         ((uint32_t *)(SGPT_BASE + 0x08))
#define SGPT_CON            ((uint32_t *)(SGPT_BASE + 0x10))
#define SGPT_CLK            ((uint32_t *)(SGPT_BASE + 0x14))
#define SGPT_DAT            ((uint32_t *)(SGPT_BASE + 0x18))
#define SGPT_COMPARE        ((uint32_t *)(SGPT_BASE + 0x1c))
#define SGPT_CON1           ((uint32_t *)(SGPT_BASE + 0x20))
#define SGPT_CLK1           ((uint32_t *)(SGPT_BASE + 0x24))
#define SGPT_DAT1L          ((uint32_t *)(SGPT_BASE + 0x28))
#define SGPT_DAT1H          ((uint32_t *)(SGPT_BASE + 0x2c))
#define SGPT_COMPARE1L      ((uint32_t *)(SGPT_BASE + 0x30))
#define SGPT_COMPARE1H      ((uint32_t *)(SGPT_BASE + 0x34))
#define SGPT_STATUS         1U
#define SGPT_STATUS1        2U
#define SGPT_ACK            1U
#define SGPT_ACK1           2U
#define SGPT_INT_EN         0x0001U
#define SGPT_INT_EN1        0x0002U
#define SGPT_DIS            0x0000U
#define SGPT_EN             0x0001U
#define SGPT_FREERUN        0x0030U
#define SGPT_KEEPGO         0x0020U
#define SGPT_ONESHOT        0x0000U
#define SGPT_REPEAT         0X0010U
#define SGPT_RTC_CLK        0x0010U
#define SGPT_CLK_DIV1       0X0000U
#define SGPT_CLK_SETTING    (SGPT_RTC_CLK | SGPT_CLK_DIV1)
#define TIMER_MAX_TRY_TIMES 10000

#endif /* DRV_TIMER_PLATFORM_MTK_TIMER_REG_H */
