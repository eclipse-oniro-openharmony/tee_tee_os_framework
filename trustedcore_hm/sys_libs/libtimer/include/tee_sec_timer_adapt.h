/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: sec timer function
 * Create: 2022-04-22
 */
#ifndef LIBTIMER_SEC_TIMER_ADAPT_H
#define LIBTIMER_SEC_TIMER_ADAPT_H

timer_event *sec_time_event_create(sw_timer_event_handler handler, int32_t timer_class, void *priv_data);
uint32_t sec_time_event_destroy(timer_event *t_event);
uint32_t sec_time_event_start(timer_event *t_event, timeval_t *time);
uint32_t sec_time_event_stop(timer_event *t_event);
uint32_t sec_time_event_check(timer_notify_data_kernel *timer_data);
#endif