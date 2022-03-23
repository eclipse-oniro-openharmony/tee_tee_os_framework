/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Rtc timer functions
 * Author: hepengfei hepengfei7@huawei.com
 * Create: 2019-08-20
 */
#include "timer_rtc.h"
#include <hmlog.h>
#include <register_ops.h>
#include <rtc_reg.h>
#include <timer_event.h>

#define RTC_CTL_ENABLE  1
#define RTC_INT_DISABLE 0x0
#define RTC_INT_ENABLE 0x1
#define RTC_INT_CLEAR 0x1

void timer_rtc_init(void)
{
    write32(RTC_CONTROL_REG, RTC_CTL_ENABLE);
    write32(RTC_IMSC, RTC_INT_DISABLE);
}

uint32_t timer_rtc_value_get(void)
{
    return read32(RTC_DATA_REG);
}

void timer_rtc_reset(uint32_t value)
{
    uint32_t cur_time;
    uint32_t new_time;

    cur_time = timer_rtc_value_get();
    new_time = value + cur_time;
    if ((new_time <= value) || (new_time <= cur_time)) {
        hm_error("integer overflow, set value is 0x%x, cur_time is 0x%x\n", value, cur_time);
        return;
    }
    write32(RTC_MATCH_REG, new_time);
    /* clear interupt */
    write32(RTC_ICR, RTC_INT_CLEAR);
    /* enable rtc interrupt */
    write32(RTC_IMSC, RTC_INT_ENABLE);
}

void timer_rtc_oneshot_fiq_handler(void)
{
    /* clear interupt */
    write32(RTC_ICR, RTC_INT_CLEAR);
    timer_event_handler(TIMER_INDEX_RTC);
}

void timer_rtc_value_set(uint32_t value)
{
    write32(RTC_LOAD_REG, value);
}
