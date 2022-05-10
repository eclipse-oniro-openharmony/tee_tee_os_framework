/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: rtc timer suspend resume function
 * Create: 2021-05-27
 */
#include "rtc_timer_pm.h"
#include <sre_hwi.h>
#include <rtc_reg.h>
#include <hmlog.h>
#include <timer_types.h>
#include <timer_rtc.h>
#include <teecall_cap.h>
#include <tee_time_api.h>

#define MS_PER_SEC     1000

static uint32_t g_rtc_suspend;
static TEE_Time g_sys_suspend;

static void get_mills_diff(TEE_Time *now, TEE_Time *diff)
{
    if (now == NULL || diff == NULL)
        return;

    if (now->millis >= g_sys_suspend.millis) {
        diff->millis = now->millis - g_sys_suspend.millis;
    } else if (now->seconds >= g_sys_suspend.seconds) {
        diff->millis = MS_PER_SEC - g_sys_suspend.millis + now->millis;
        diff->seconds = diff->seconds + 1;
    } else if (now->seconds < g_sys_suspend.seconds) {
        diff->millis = MS_PER_SEC - g_sys_suspend.millis + now->millis;
        diff->seconds = diff->seconds - 1;
    } else {
        diff->millis = 0;
    }

    return;
}

static int32_t calc_adjust_timer(TEE_Time *adjust_time)
{
    TEE_Time now;
    TEE_Time diff;
    if (adjust_time == NULL)
        return TMR_DRV_ERROR;

    /* calculate the sleep time */
    adjust_time->seconds = timer_rtc_value_get() - g_rtc_suspend;

    /* maybe syscnt counting incorrectly during sleep */
    TEE_GetSystemTime(&now);
    if (now.seconds >= g_sys_suspend.seconds)
        diff.seconds = now.seconds - g_sys_suspend.seconds;
    else
        diff.seconds = g_sys_suspend.seconds;

    get_mills_diff(&now, &diff);
    if (now.seconds < g_sys_suspend.seconds)
        adjust_time->seconds += diff.seconds;
    else
        adjust_time->seconds = (adjust_time->seconds > diff.seconds) ? (adjust_time->seconds  - diff.seconds) : 0;

    adjust_time->millis = diff.millis;
    return TMR_DRV_SUCCESS;
}

int32_t rtc_timer_suspend(void)
{
    TEE_GetSystemTime(&g_sys_suspend);
    g_rtc_suspend = timer_rtc_value_get();
    return TMR_DRV_SUCCESS;
}

int32_t rtc_timer_resume(void)
{
    uint32_t ret;
    TEE_Time adjust_time;

    ret = rtc_interrupt_resume();
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("resume rtc irq fail\n");
        return TMR_DRV_ERROR;
    }

    ret = calc_adjust_timer(&adjust_time);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("calculate sleep time fail\n");
        return ret;
    }

    teecall_cap_time_adjust(adjust_time.seconds, adjust_time.millis);
    return TMR_DRV_SUCCESS;
}
