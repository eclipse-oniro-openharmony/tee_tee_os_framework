/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Header file for timer_event
 * Create: 2021-05-27
 */

#ifndef RTC_TIMER_DRIVER_TIMER_EVENT_H
#define RTC_TIMER_DRIVER_TIMER_EVENT_H

#include <stdint.h>
#include <stdbool.h>
#include <sys_timer.h>

uint32_t timer_event_destory_with_uuid(timer_event *timer_node, const struct tee_uuid *uuid, bool real_event);

timer_event *timer_event_create(const sw_timer_event_handler handler, int32_t timer_class,
                                const void *priv_data, const struct tee_uuid *uuid);

int64_t timer_expire_get(const timer_event *timer_node);

void timer_set_expire(timeval_t *time_next_tick);

uint32_t timer_event_start(timer_event *timer_node, const timeval_t *time, const struct tee_uuid *uuid);

void timer_event_handler(uint32_t timer_id);

uint32_t timer_event_stop(timer_event *timer_node, const struct tee_uuid *uuid, bool real_event);

uint32_t timer_data_check_by_uuid(timer_notify_data_kernel *timer_data, const struct tee_uuid *uuid);

struct timer_cpu_info *get_timer_cpu_info();

int64_t timer_expire_value_get(const timer_event *timer_node, bool real_event);

uint32_t release_timer_event_by_uuid(const TEE_UUID *uuid);
#endif /* RTC_TIMER_DRIVER_TIMER_EVENT_H */
