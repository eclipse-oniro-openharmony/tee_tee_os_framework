/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for timer_rtc
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_PLATFORM_RTC_TIMER_RTC_H
#define DRV_TIMER_PLATFORM_RTC_TIMER_RTC_H

#include <stdint.h>

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

void timer_rtc_init(void);
void timer_rtc_value_set(uint32_t time);
uint32_t timer_rtc_value_get(void);
void timer_rtc_oneshot_fiq_handler(void);
void timer_rtc_reset(uint32_t value);

#endif /* DRV_TIMER_PLATFORM_RTC_TIMER_RTC_H */
