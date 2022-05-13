/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: time stub api define in this file.
 * Create: 2022-04-22
 */

#include <tee_defines.h>
#include <securec.h>
#include <time.h>
#include <sys_timer.h>

timer_event *tee_time_event_create(sw_timer_event_handler handler, int32_t timer_class, void *priv_data)
{
    (void)handler;
    (void)timer_class;
    (void)priv_data;
    return NULL;
}

uint32_t tee_time_event_destroy(timer_event *t_event)
{
    (void)t_event;
    return TMR_ERR;
}

uint32_t tee_time_event_start(timer_event *t_event, timeval_t *time)
{
    (void)t_event;
    (void)time;
    return TMR_ERR;
}

uint32_t tee_time_event_stop(timer_event *t_event)
{
    (void)t_event;
    return TMR_ERR;
}

uint32_t tee_time_event_check(timer_notify_data_kernel *timer_data)
{
    (void)timer_data;
    return TMR_ERR;
}

uint64_t tee_time_event_get_expire(timer_event *t_event)
{
    (void)t_event;
    return TMR_ERR;
}

unsigned int sleep(unsigned int seconds)
{
    (void)seconds;
    return TMR_ERR;
}

int nanosleep(const struct timespec *req, struct timespec *rem)
{
    (void)req;
    (void)rem;
    return TMR_ERR;
}

/*
 * renew_hmtimer_job_handler returns OK when CONFIG_TIMER_DISABLE macro takes effect,
 * as tarunner/taloader using it during loading TA period
 */
int renew_hmtimer_job_handler(void)
{
    return TMR_OK;
}

/*
 * hm_timer_init returns OK when CONFIG_TIMER_DISABLE macro takes effect,
 * as tarunner/taloader using it during loading TA period
 */
int hm_timer_init(void)
{
    return TMR_OK;
}

struct tm *localtime(const time_t *t)
{
    (void)t;
    return NULL;
}

uint32_t adjust_sys_time(const struct tee_time_t *time)
{
    (void)time;
    return TMR_ERR;
}

void TEE_GetSystemTime(TEE_Time *time)
{
    (void)time;
}

TEE_Result TEE_Wait(uint32_t mill_second)
{
    (void)mill_second;
    return TMR_ERR;
}

TEE_Result TEE_GetTAPersistentTime(TEE_Time *time)
{
    (void)time;
    return TMR_ERR;
}

TEE_Result TEE_SetTAPersistentTime(TEE_Time *time)
{
    (void)time;
    return TMR_ERR;
}

void TEE_GetREETime(TEE_Time *time)
{
    (void)time;
}

void TEE_GetREETimeStr(char *time_str, uint32_t time_str_len)
{
    (void)time_str;
    (void)time_str_len;
}

TEE_Result tee_antiroot_create_timer(uint32_t time_seconds)
{
    (void)time_seconds;
    return TMR_ERR;
}

TEE_Result tee_antiroot_destory_timer(void)
{
    return TMR_ERR;
}

void get_sys_rtc_time(TEE_Time *time)
{
    if (time != NULL)
        (void)memset_s(time, sizeof(*time), 0, sizeof(*time));
}

void gen_sys_date_time(uint32_t secs, tee_date_time_kernel *date_time)
{
    (void)secs;
    (void)date_time;
}

void get_sys_date_time(tee_date_time_kernel *time_date)
{
    (void)time_date;
}

void tee_msleep(uint32_t delay)
{
    (void)delay;
}

void delay_us(uint32_t delay)
{
    (void)delay;
}

void delay_ms(uint32_t msec)
{
    (void)msec;
}

uint64_t tee_read_time_stamp(void)
{
    return TMR_ERR;
}

void release_timer_event(const TEE_UUID *uuid)
{
    (void)uuid;
}

int set_ta_timer_permission(const TEE_UUID *uuid, uint64_t permission)
{
    (void)uuid;
    (void)permission;
    return TMR_ERR;
}

void get_ree_time_str(char *time_str, uint32_t time_str_len)
{
    (void)time_str;
    (void)time_str_len;
}

uint32_t __SRE_SwMsleep(uint32_t msec)
{
    (void)msec;
    return TMR_ERR;
}