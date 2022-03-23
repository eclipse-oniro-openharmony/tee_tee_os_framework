/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for timer_event
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_PLATFORM_TIMER_EVENT_H
#define DRV_TIMER_PLATFORM_TIMER_EVENT_H

#include <stdint.h>
#include <stdbool.h>
#include <sys_timer.h>

uint32_t timer_event_destory_with_uuid(timer_event *timer_node, const struct tee_uuid *uuid, bool real_event);

timer_event *timer_event_create(const sw_timer_event_handler handler, int32_t timer_class,
                                const void *priv_data, int32_t pid);

int64_t timer_expire_get(const timer_event *timer_node);

uint32_t timer_event_start(timer_event *timer_node, timeval_t *time, const struct tee_uuid *uuid);

void timer_event_handler(uint32_t timer_id);

uint32_t timer_event_stop(timer_event *timer_node, const struct tee_uuid *uuid, bool real_event);

uint32_t timer_data_check_by_uuid(timer_notify_data_kernel *timer_data, const struct tee_uuid *uuid);

struct timer_cpu_info *get_timer_cpu_info();

int64_t timer_value_sub(const timeval_t *time_val_1, const timeval_t *time_val_2);

int64_t timer_expire_value_get(const timer_event *timer_node, bool real_event);

uint32_t release_timer_event_by_uuid(const TEE_UUID *uuid);
#endif /* DRV_TIMER_PLATFORM_TIMER_EVENT_H */
