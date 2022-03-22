/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Header file for timer_rtc
 * Create: 2021-05-27
 */

#ifndef RTC_TIMER_DRIVER_TIMER_RTC_H
#define RTC_TIMER_DRIVER_TIMER_RTC_H

#include <stdint.h>

#define TIMER_CLK_FREQ       1

struct rtc_time {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

void rtc_timer_hardware_init(void);
uint32_t rtc_timer_interrupt_init(void);
uint32_t rtc_interrupt_resume(void);
uint32_t timer_rtc_value_get(void);
void timer_rtc_oneshot_fiq_handler(void);
void timer_rtc_reset(uint32_t value);
void timer_tick_trigger(uint64_t clock_cycles);
void timer_disable(void);
#endif /* RTC_TIMER_DRIVER_TIMER_RTC_H */
