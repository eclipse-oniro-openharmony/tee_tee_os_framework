/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Common functions of timer module.
 * Create: 2019-08-20
 */
#include "timer_pm.h"
#include <hmlog.h>
#include "timer_hw.h"
#include "timer_reg.h"
#include "timer_types.h"
#include "timer_sys.h"
#include "sys_timer.h"
#include "timer_hw.h"
#include "timer_event.h"
#include "timer_interrupt.h"

#define FREE_RUNNING_TIMER_OFFSET 0x20
#define TIMER_CLK_FRAC_FREQ       16
#define INT32_POSITIVE_MAX        2147483647

#ifdef TIMER_EVENT_SUPPORT
static timeval_t g_suspend_event_time;

static uint64_t get_resume_value(void)
{
    timeval_t next_tick;
    uint64_t clock_cycles;
    uint32_t ret;
    timeval_t now;
    struct timer_cpu_info *local_cpu_info = NULL;
    timeval_t expires_timer;
    timeval_t expires_rtc;

    if (timer_get_value(TICK_TIMER_BASE, TICK_TIMER_NUM) == TIMER_VALUE_INVALID)
        return TIMER_VALUE_INVALID;

    now.tval64 = timer_stamp_value_read();
    local_cpu_info = get_timer_cpu_info();
    expires_timer = local_cpu_info->expires_next[TIMER_INDEX_TIMER];
#ifdef SOFT_RTC_TICK
    expires_rtc = local_cpu_info->expires_next[TIMER_INDEX_RTC];
    if (expires_rtc.tval64 < expires_timer.tval64)
        expires_timer = expires_rtc;
#else
    (void)expires_rtc;
#endif

    if (expires_timer.tval.sec == INT32_POSITIVE_MAX)
        return TIMER_VALUE_INVALID;

    if (expires_timer.tval64 <= now.tval64)
        return MIN_CLOCK_CYCLES;

    next_tick.tval64 = timer_value_sub(&expires_timer, &now);

    ret = timer_timeval_to_clock(&next_tick, TIMER_GENERIC, &clock_cycles);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("get clock cycles fail\n");
        clock_cycles = MIN_CLOCK_CYCLES;
    }

    return clock_cycles;
}

static void timer_value_resume(void)
{
    uint64_t user_time_val = get_resume_value();
    if (user_time_val != TIMER_VALUE_INVALID) {
        timer_set_value(TICK_TIMER_BASE, TICK_TIMER_NUM, MODE_ONESHOT, user_time_val);
        timer_enable(TICK_TIMER_BASE, TICK_TIMER_NUM);
    }
}
#endif

static int32_t timer_hwi_resume()
{
    uint32_t ret;
    ret = timer_hwi_resume_all();
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("resume timer interrupt failed!\n");
        return ret;
    }

    ret = timer_interrupt_enable_all();
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("enable timer interrupt failed!\n");
        return ret;
    }

    return TMR_DRV_SUCCESS;
}

#ifdef TIMER_EVENT_SUPPORT
static void timer_event_restore(void)
{
    timeval_t sleep_time;
    timeval_t resume_time;
    timer_event *temp = NULL;

    struct timer_cpu_info *local_cpu_info = get_timer_cpu_info();
    if (local_cpu_info == NULL) {
        hm_error("cpu info is invalid\n");
        return;
    }

    struct timer_clock_info *clock_info = &local_cpu_info->clock_info[TIMER_INDEX_TIMER];
    if (clock_info == NULL) {
        hm_error("clock info is invalid\n");
        return;
    }

    resume_time.tval64 = (int64_t)timer_stamp_value_read();
    if (resume_time.tval64 <= g_suspend_event_time.tval64)
        return;

    if (dlist_empty(&clock_info->active)) {
        local_cpu_info->expires_next[TIMER_INDEX_TIMER].tval64 = TIMEVAL_MAX;
        return;
    }
    /* calc the sleep time */
    sleep_time.tval64 = (int64_t)timer_value_sub(&resume_time, &g_suspend_event_time);

    /* add the sleep time to expires_next in timer60 */
    if (local_cpu_info->expires_next[TIMER_INDEX_TIMER].tval64 != TIMEVAL_MAX)
        local_cpu_info->expires_next[TIMER_INDEX_TIMER].tval64 =
            (int64_t)timer_value_add(&local_cpu_info->expires_next[TIMER_INDEX_TIMER], &sleep_time);

    /* add the sleep time in each event in timer60 list */
    clock_info = &local_cpu_info->clock_info[TIMER_INDEX_TIMER];
    if (!dlist_empty(&clock_info->active)) {
        dlist_for_each_entry(temp, &clock_info->active, timer_event, node)
            temp->expires.tval64 = (int64_t)timer_value_add(&temp->expires, &sleep_time);
    }
}

/* calc the sleep time */
static void cacluate_sleep_time(timeval_t *sleep_time)
{
    uint64_t counter_cur = timer_get_value(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
    if (counter_cur > TIMER_COUNT_MAX) {
        hm_error("free running timer error\n");
        return;
    }

    uint32_t sleep_time_pc = TIMER_COUNT_MAX - (uint32_t)counter_cur;
    timer_disable(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
    uint64_t sleep_time_hex = (uint64_t)((uint64_t)sleep_time_pc * TIMER_CLK_FRAC_FREQ);
    if (sleep_time_hex / TIMER_CLK_FREQ > INT32_POSITIVE_MAX) {
        hm_error("sleep time sec left error\n");
        return;
    }

    sleep_time->tval.sec = (int32_t)(sleep_time_hex / TIMER_CLK_FREQ);
    uint64_t nsec_left  = sleep_time_hex % TIMER_CLK_FREQ;
    if (TIMER_COUNT_MAX_64BIT / NS_PER_SECONDS < nsec_left) {
        hm_error("sleep time nsec left error\n");
        return;
    }

    uint64_t nsec_left_2 = nsec_left * NS_PER_SECONDS / TIMER_CLK_FREQ;
    if (nsec_left_2 > INT32_POSITIVE_MAX) {
        hm_error("sleep time nsec left_2 error\n");
        return;
    }

    sleep_time->tval.nsec = (int32_t)nsec_left_2;
}

void timer_s3_event_restore(void)
{
    timeval_t sleep_time;

    cacluate_sleep_time(&sleep_time);
    timer_resume_stamp(sleep_time);
    set_timer_cycles_count_old_zero();

    timer_event *temp = NULL;
    struct timer_cpu_info *local_cpu_info = get_timer_cpu_info();
    if (local_cpu_info == NULL) {
        hm_error("cpu info is invalid\n");
        return;
    }

    struct timer_clock_info *clock_info = &local_cpu_info->clock_info[TIMER_INDEX_TIMER];
    if (clock_info == NULL) {
        hm_error("clock info is invalid\n");
        return;
    }

    /* add the sleep time to expires_next in timer60 */
    if (local_cpu_info->expires_next[TIMER_INDEX_TIMER].tval64 != TIMEVAL_MAX)
        local_cpu_info->expires_next[TIMER_INDEX_TIMER].tval64 =
            (int64_t)timer_value_add(&local_cpu_info->expires_next[TIMER_INDEX_TIMER], &sleep_time);

    /* add the sleep time in each event in timer60 list */
    clock_info = &local_cpu_info->clock_info[TIMER_INDEX_TIMER];
    if (!dlist_empty(&clock_info->active)) {
        dlist_for_each_entry(temp, &clock_info->active, timer_event, node)
            temp->expires.tval64 = (int64_t)timer_value_add(&temp->expires, &sleep_time);
    }

    /* configure the timer10 to the original frequency */
#ifdef TIMER_S3_ADJUST_FREQ
    timer_free_run_restore_freq();
#endif
    timer_set_value(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM, MODE_FREE_RUNNING, TIMER_COUNT_MAX);
    timer_enable(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
}

static void timer_event_store(uint32_t flag)
{
    /* store the timer value when suspend */
    g_suspend_event_time.tval64 = (int64_t)timer_stamp_value_read();
#ifdef TIMER_S3_ADJUST_FREQ
    if (flag == TIMER_SUSPEND_S3) {
        set_timer_cycles_count_old_zero();
        /* configure the timer10 to reduce frequency */
        timer_disable(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
        timer_free_run_reduce_freq();
        timer_set_value(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM, MODE_FREE_RUNNING, TIMER_COUNT_MAX);
        timer_enable(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
    }
#endif
    (void)flag;
}
#endif

int32_t timer_resume(uint32_t flag)
{
    hm_debug("timer resume start\n");
    int32_t ret;

    /* timer10 is alway on,so do not need to init timer60 when resume */
    timer_clk_init();

    ret = timer_hwi_resume();
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("hwi resume failed\n");
        return TMR_DRV_ERROR;
    }

#ifdef RESUME_FREE_TIMER_FEATURE
    resume_freerunning_timer(flag);
#endif

#ifdef TIMER_EVENT_SUPPORT
#ifdef TIMER_S3_ADJUST_FREQ
    if (flag == TIMER_RESUME_S3)
        timer_s3_event_restore();
    else
        timer_event_restore();
#else
    timer_event_restore();
#endif
    timer_value_resume();
#endif
    /*
     * Must set timer10 to non secure to keep timer counter continue to decrease when deep sleep
     * else timer counter stopped when system goto deep sleep.
     * When system resume, set timer to secure
     */
    set_timer_secure();
    (void)flag;
    return TMR_DRV_SUCCESS;
}

int32_t timer_suspend(uint32_t flag)
{
    hm_debug("timer suspend start\n");
    (void)flag;
    /* free running timer set */
    set_timer_non_secure();

    /*
     * For tick timer, we need to save the timer value when the timer is suspend, in order
     * to resume the timer when cpu resume.
     * Add when debugging Anti-root
     */
#ifdef TIMER_EVENT_SUPPORT
    timer_event_store(flag);
    timer_disable(TICK_TIMER_BASE, TICK_TIMER_NUM);
#ifdef RESUME_FREE_TIMER_FEATURE
    save_freerunning_timer(flag);
#endif

#endif
    return TMR_DRV_SUCCESS;
}
