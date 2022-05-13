/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: rtc timer adapt api define in this file.
 * Create: 2022-04-22
 */
#include <sre_syscalls_id.h>
#include <hmdrv.h>
#include <sys_timer.h>
#include <hmlog.h>
#include <tee_rtc_adapt.h>

static uint32_t rtc_read_time_stamp(void)
{
    uint64_t args[] = { 0 };
    return hm_drv_call(SW_SYSCALL_GET_RTC_TIME, args, ARRAY_SIZE(args));
}

static timer_event *rtc_timer_event_create(sw_timer_event_handler handler, int32_t timer_class, void *priv_data)
{
    uint32_t ret;
    uint64_t time_event;
    uint64_t args[] = {
        (uint64_t)(uintptr_t)&time_event,
        (uint64_t)(uintptr_t)priv_data
    };

    (void)handler;
    (void)timer_class;
    ret = hm_drv_call(SW_SYSCALL_TIMER_CREATE, args, ARRAY_SIZE(args));
    if (ret != TMR_OK)
        return NULL;

    return (timer_event *)(uintptr_t)time_event;
}

static uint32_t rtc_timer_event_start(timer_event *t_event, timeval_t *time)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)t_event,
        (uint64_t)(uintptr_t)time
    };

    return hm_drv_call(SW_SYSCALL_TIMER_START, args, ARRAY_SIZE(args));
}

static uint32_t rtc_timer_event_stop(timer_event *t_event)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)t_event,
    };

    return hm_drv_call(SW_SYSCALL_TIMER_STOP, args, ARRAY_SIZE(args));
}

static uint32_t rtc_timer_event_destroy(timer_event *t_event)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)t_event,
    };

    return hm_drv_call(SW_SYSCALL_TIMER_DESTORY, args, ARRAY_SIZE(args));
}

static uint32_t rtc_time_event_get_remain(timer_event *t_event)
{
    timeval_t expire;
    uint32_t cur_time;
    uint32_t remain;
    uint64_t args[] = {
        (uint64_t)(uintptr_t)t_event,
        (uint64_t)(uintptr_t)&expire
    };
    uint32_t ret;

    ret = hm_drv_call(SW_SYSCALL_GET_TIMER_EXPIRE, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        hm_error("get expire fail\n");
        return TIMER_INV_VALUE;
    }

    cur_time = rtc_read_time_stamp();
    if ((expire.tval.sec <= 0) || ((uint32_t)expire.tval.sec < cur_time)) {
        hm_error("get invalid expire\n");
        return TIMER_INV_VALUE;
    }

    remain = expire.tval.sec - cur_time;
    return remain;
}

static uint32_t rtc_timer_event_check(timer_notify_data_kernel *timer_data)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)timer_data,
    };

    return hm_drv_call(SW_SYSCALL_CHECK_TIMER, args, ARRAY_SIZE(args));
}

static struct rtc_timer_ops_t g_rtc_timer_ops = {
    rtc_read_time_stamp,
    rtc_timer_event_create,
    rtc_timer_event_destroy,
    rtc_timer_event_start,
    rtc_timer_event_stop,
    rtc_time_event_get_remain,
    rtc_timer_event_check,
};

struct rtc_timer_ops_t *get_rtc_time_ops(void)
{
    return &g_rtc_timer_ops;
}
