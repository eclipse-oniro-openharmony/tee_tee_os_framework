/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tee time event api define in this file.
 * Create: 2022-04-22
 */
#include <sys_timer.h>
#include <tee_time_adapt.h>
#include <sys/usrsyscall_ext.h>

timer_event *tee_time_event_create(sw_timer_event_handler handler, int32_t timer_class, void *priv_data)
{
    struct timer_ops_t *time_ops = NULL;
    time_ops = get_time_ops();
    if (time_ops == NULL)
        return NULL;

    return time_ops->time_event_create(handler, timer_class, priv_data);
}

uint32_t tee_time_event_start(timer_event *t_event, timeval_t *time)
{
    struct timer_ops_t *time_ops = NULL;
    time_ops = get_time_ops();
    if (time_ops == NULL)
        return TMR_ERR;

    return time_ops->time_event_start(t_event, time);
}

uint32_t tee_time_event_stop(timer_event *t_event)
{
    struct timer_ops_t *time_ops = NULL;
    time_ops = get_time_ops();
    if (time_ops == NULL)
        return TMR_ERR;

    return time_ops->time_event_stop(t_event);
}

uint32_t tee_time_event_check(timer_notify_data_kernel *timer_data)
{
    struct timer_ops_t *time_ops = NULL;
    time_ops = get_time_ops();
    if (time_ops == NULL)
        return TMR_ERR;

    return time_ops->time_event_check(timer_data);
}

uint64_t tee_time_event_get_expire(timer_event *t_event)
{
    struct timer_ops_t *time_ops = NULL;
    time_ops = get_time_ops();
    if (time_ops == NULL)
        return TMR_ERR;

    return time_ops->time_event_get_expire(t_event);
}

uint32_t tee_time_event_destroy(timer_event *t_event)
{
    struct timer_ops_t *time_ops = NULL;
    time_ops = get_time_ops();
    if (time_ops == NULL)
        return TMR_ERR;

    return time_ops->time_event_destroy(t_event);
}
