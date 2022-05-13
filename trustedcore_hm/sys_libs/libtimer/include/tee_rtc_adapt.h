/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: rtc timer function
 * Create: 2022-04-22
 */
#ifndef LIBTIMER_RTC_ADAPT_H
#define LIBTIMER_RTC_ADAPT_H

#define SHIFT_32        32U

typedef uint32_t (*timer_get_rtc_seconds)(void);
typedef timer_event *(*timer_time_event_create)(sw_timer_event_handler handler, int32_t timer_class, void *priv_data);
typedef uint32_t (*timer_time_event_destroy)(timer_event *t_event);
typedef uint32_t (*timer_time_event_start)(timer_event *t_event, timeval_t *time);
typedef uint32_t (*timer_time_event_stop)(timer_event *t_event);
typedef uint32_t (*timer_time_event_get_remain)(timer_event *t_event);
typedef uint32_t (*timer_time_event_check)(timer_notify_data_kernel *timer_data);

struct rtc_timer_ops_t {
    timer_get_rtc_seconds get_rtc_seconds;
    timer_time_event_create rtc_time_event_create;
    timer_time_event_destroy rtc_time_event_destroy;
    timer_time_event_start rtc_time_event_start;
    timer_time_event_stop rtc_time_event_stop;
    timer_time_event_get_remain rtc_time_event_get_remain;
    timer_time_event_check rtc_time_event_check;
};

struct rtc_timer_ops_t *get_rtc_time_ops(void);
#endif