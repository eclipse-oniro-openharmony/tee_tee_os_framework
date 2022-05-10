/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: rtc timer function
 * Create: 2022-04-22
 */
#ifndef LIBTIMER_TIMER_EVENT_H
#define LIBTIMER_TIMER_EVENT_H
#include <sys_timer.h>

timer_event *tee_time_event_create(sw_timer_event_handler handler, int32_t timer_class, void *priv_data);
uint32_t tee_time_event_destroy(timer_event *t_event);
uint32_t tee_time_event_start(timer_event *t_event, timeval_t *time);
uint32_t tee_time_event_stop(timer_event *t_event);
uint32_t tee_time_event_check(timer_notify_data_kernel *timer_data);
uint64_t tee_time_event_get_expire(timer_event *t_event);

#endif
