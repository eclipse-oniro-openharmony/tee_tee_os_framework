/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Rtc timer functions
 * Create: 2019-08-20
 */
#include "timer_rtc.h"
#include <register_ops.h>

#define RTC_CTL_ENABLE  1
#define RTC_INT_DISABLE 0x0
#define RTC_INT_ENABLE 0x1
#define RTC_INT_CLEAR 0x1

void timer_rtc_init(void)
{
}

uint32_t timer_rtc_value_get(void)
{
    return 0;
}

void timer_rtc_reset(uint32_t value)
{
    (void)value;
}

void timer_rtc_oneshot_fiq_handler(void)
{
}

void timer_rtc_value_set(uint32_t value)
{
    (void)value;
}
