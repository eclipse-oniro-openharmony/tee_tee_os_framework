/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: rtc timer adapt api define in this file.
 * Create: 2022-04-22
 */
#include <sre_syscalls_id.h>
#include <sys_timer.h>
#include <hmlog.h>
#include <tee_timer_call.h>
#include <tee_rtc_adapt.h>
#include <tee_sec_timer_adapt.h>
#include <tee_time_sys.h>

static uint32_t rtc_get_secure_rtc_time(void)
{
    uint64_t args[] = { 0 };
    uint32_t ret;

    ret = hmtimer_call(SW_SYSCALL_GET_RTC_TIME, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        hm_error("get secure rtc time fail\n");
        return TIMER_INV_VALUE;
    }
    return (uint32_t)args[0];
}

static uint32_t rtc_time_event_get_remain(timer_event *t_event)
{
    uint32_t ret;
    timeval_t expire_time;
    timeval_t cur_time;
    uint64_t args[] = { (uint64_t)(uintptr_t)t_event, 0, 0 };

    if (t_event == NULL)
        return TIMER_INV_VALUE;

    ret = hmtimer_call(SW_SYSCALL_GET_TIMER_EXPIRE, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        hm_error("get expire fail\n");
        return TIMER_INV_VALUE;
    }
    expire_time.tval64 = (args[1] | (args[2] << SHIFT_32));

    cur_time.tval64 = (int64_t)tee_read_time_stamp();
    if (cur_time.tval64 <= 0) {
        hm_error("get current time failed\n");
        return TIMER_INV_VALUE;
    }

    expire_time.tval64 = expire_time.tval64 - cur_time.tval64;
    return expire_time.tval.sec;
}

static struct rtc_timer_ops_t g_rtc_timer_ops = {
    rtc_get_secure_rtc_time,
    sec_time_event_create,
    sec_time_event_destroy,
    sec_time_event_start,
    sec_time_event_stop,
    rtc_time_event_get_remain,
    sec_time_event_check,
};

struct rtc_timer_ops_t *get_rtc_time_ops(void)
{
    return &g_rtc_timer_ops;
}
