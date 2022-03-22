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
#include <sys_timer.h>
#include <timer_rtc.h>

static uint64_t g_rtc_suspend;

int32_t rtc_timer_suspend(void)
{
    /* nothing to do for s3 */
    return TMR_DRV_SUCCESS;
}

int32_t rtc_timer_resume(void)
{
    uint32_t ret;

    ret = rtc_interrupt_resume();
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("resume rtc irq fail\n");
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

int32_t rtc_timer_suspend_s4(void)
{
    /* for S4 adjust time */
    g_rtc_suspend = (uint64_t)timer_rtc_value_get();
    return TMR_DRV_SUCCESS;
}

int32_t rtc_timer_resume_s4(void)
{
    uint32_t ret;
    uint64_t rtc_resume;
    timeval_t sleep_time;

    ret = rtc_interrupt_resume();
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("resume rtc irq fail\n");
        return TMR_DRV_ERROR;
    }

    /* for S4 adjust time */
    rtc_resume = timer_rtc_value_get();
    sleep_time.tval.sec = rtc_resume - g_rtc_suspend;
    teecall_cap_time_adjust(sleep_time.tval.sec, 0);
    return TMR_DRV_SUCCESS;
}
