/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: The timer related functions export to other moudle.
 * Create: 2019-08-20
 */

#include <timer_export.h>

#include <timer.h>
#include "securec.h"

#ifdef CONFIG_TIMER_DISABLE
__attribute__((visibility("default"))) UINT32 __SRE_SwMsleep(UINT32 millisecond)
{
    (void)millisecond;
    return TMR_ERR;
}

timer_event *__SRE_TimerEventCreate(sw_timer_event_handler handler, INT32 timer_class, void *priv_data)
{
    (void)handler;
    (void)timer_class;
    (void)priv_data;
    return NULL;
}

UINT32 __SRE_TimerEventDestroy(timer_event *t_event)
{
    (void)t_event;
    return TMR_ERR;
}

UINT32 __SRE_TimerEventStart(timer_event *t_event, timeval_t *time)
{
    (void)t_event;
    (void)time;
    return TMR_ERR;
}

UINT32 __SRE_TimerEventStop(timer_event *t_event)
{
    (void)t_event;
    return TMR_ERR;
}

UINT64 __SRE_TimerGetExpire(timer_event *t_event)
{
    (void)t_event;
    return TMR_ERR;
}

UINT32 __SRE_TimerCheck(timer_notify_data_kernel *timer_data)
{
    (void)timer_data;
    return TMR_ERR;
}

void __get_startup_time(tee_time_kernel *time, uint32_t *rtc_time)
{
    (void)time;
    (void)rtc_time;
}

void tee_timer_drv_init(void)
{
    return;
}

UINT64 __SRE_ReadTimestamp(void)
{
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

void __init_startup_time_kernel(uint32_t rtc_time)
{
    (void)rtc_time;
}

uint32_t __adjust_sys_time(const struct tee_time_t *time)
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

__attribute__((visibility("default"))) void TEE_GetREETime(TEE_Time *time)
{
    (void)time;
}

void TEE_GetREETimeStr(char *time_str, uint32_t time_str_len)
{
    (void)time_str;
    (void)time_str_len;
}

__attribute__((visibility("default"))) TEE_Result TEE_ANTI_ROOT_CreateTimer(uint32_t time_seconds)
{
    (void)time_seconds;
    return TMR_ERR;
}

__attribute__((visibility("default"))) TEE_Result TEE_ANTI_ROOT_DestoryTimer(void)
{
    return TMR_ERR;
}

void get_sys_rtc_time(TEE_Time *time)
{
    if (time != NULL)
        (void)memset_s(time, sizeof(*time), 0, sizeof(*time));
}

__attribute__((visibility("default"))) void __gen_sys_date_time(uint32_t secs,
                                                                tee_date_time_kernel *date_time)
{
    (void)secs;
    (void)date_time;
}

void __get_sys_date_time(tee_date_time_kernel *time_date)
{
    (void)time_date;
}

uint32_t SRE_TimerEventStart(timer_event *t_event, timeval_t *time)
{
    (void)t_event;
    (void)time;
    return TMR_ERR;
}

uint32_t SRE_TimerEventStop(timer_event *t_event)
{
    (void)t_event;
    return TMR_ERR;
}

timer_event *SRE_TimerEventCreate(sw_timer_event_handler handler, int32_t timer_class, void *priv_data)
{
    (void)handler;
    (void)timer_class;
    (void)priv_data;
    return NULL;
}

uint32_t SRE_TimerEventDestroy(timer_event *t_event)
{
    (void)t_event;
    return TMR_ERR;
}

void SRE_DelayMs(uint32_t delay)
{
    (void)delay;
}

void SRE_DelayUs(uint32_t delay)
{
    (void)delay;
}

uint64_t SRE_ReadTimestamp(void)
{
    return TMR_ERR;
}

void release_timer_event(const TEE_UUID *uuid)
{
    (void)uuid;
}

__attribute__((visibility("default"))) int set_ta_timer_permission(const TEE_UUID *uuid,
                                                                   uint64_t permission)
{
    (void)uuid;
    (void)permission;
    return TMR_ERR;
}

#else /* not define CONFIG_TIMER_DISABLE */

__attribute__((visibility("default"))) UINT32 __SRE_SwMsleep(UINT32 millisecond)
{
    return SRE_SwMsleep(millisecond);
}

timer_event *__SRE_TimerEventCreate(sw_timer_event_handler handler, INT32 timer_class, void *priv_data)
{
    return SRE_TimerEventCreate(handler, timer_class, priv_data);
}

UINT32 __SRE_TimerEventDestroy(timer_event *t_event)
{
    return SRE_TimerEventDestroy(t_event);
}

UINT32 __SRE_TimerEventStart(timer_event *t_event, timeval_t *time)
{
    return SRE_TimerEventStart(t_event, time);
}

UINT32 __SRE_TimerEventStop(timer_event *t_event)
{
    return SRE_TimerEventStop(t_event);
}

UINT64 __SRE_TimerGetExpire(timer_event *t_event)
{
    return SRE_TimerGetExpire(t_event);
}

UINT32 __SRE_TimerCheck(timer_notify_data_kernel *timer_data)
{
    return SRE_TimerCheck(timer_data);
}

void __get_startup_time(tee_time_kernel *time, uint32_t *rtc_time)
{
    (void)time;
    (void)rtc_time;
}

void tee_timer_drv_init(void)
{
}

UINT64 __SRE_ReadTimestamp(void)
{
    return SRE_ReadTimestamp();
}

unsigned int sleep(unsigned int seconds)
{
    return sleep_internal(seconds);
}

int nanosleep(const struct timespec *req, struct timespec *rem)
{
    return nanosleep_internal(req, rem);
}

int renew_hmtimer_job_handler(void)
{
    return renew_hmtimer_job_handler_internal();
}

int hm_timer_init(void)
{
    return hm_timer_init_internal();
}

struct tm *localtime(const time_t *t)
{
    return localtime_internal(t);
}

void __init_startup_time_kernel(uint32_t rtc_time)
{
    (void)rtc_time;
}

uint32_t __adjust_sys_time(const struct tee_time_t *time)
{
    return adjust_sys_time_internal(time);
}

void TEE_GetSystemTime(TEE_Time *time)
{
    tee_get_system_time(time);
}

TEE_Result TEE_Wait(uint32_t mill_second)
{
    return tee_wait(mill_second);
}

TEE_Result TEE_GetTAPersistentTime(TEE_Time *time)
{
    return get_ta_persistent_time(time);
}

TEE_Result TEE_SetTAPersistentTime(TEE_Time *time)
{
    return set_ta_persistent_time(time);
}

__attribute__((visibility("default"))) void TEE_GetREETime(TEE_Time *time)
{
    get_ree_time(time);
}

void TEE_GetREETimeStr(char *time_str, uint32_t time_str_len)
{
    get_ree_time_str(time_str, time_str_len);
}

__attribute__((visibility("default"))) TEE_Result TEE_ANTI_ROOT_CreateTimer(uint32_t time_seconds)
{
    return tee_antiroot_create_timer(time_seconds);
}

__attribute__((visibility("default"))) TEE_Result TEE_ANTI_ROOT_DestoryTimer(void)
{
    return tee_antiroot_destory_timer();
}

void get_sys_rtc_time(TEE_Time *time)
{
    get_sys_rtc_time_internal(time);
}

__attribute__((visibility("default"))) void __gen_sys_date_time(uint32_t secs,
                                                                tee_date_time_kernel *date_time)
{
    gen_sys_date_time_internal(secs, date_time);
}

void __get_sys_date_time(tee_date_time_kernel *time_date)
{
    get_sys_date_time_internal(time_date);
}

uint32_t SRE_TimerEventStart(timer_event *t_event, timeval_t *time)
{
#ifndef CONFIG_OFF_DRV_TIMER
    return timer_event_start_internal(t_event, time);
#else
    return tee_timer_event_start(t_event, time);
#endif
}

uint32_t SRE_TimerEventStop(timer_event *t_event)
{
#ifndef CONFIG_OFF_DRV_TIMER
    return timer_event_stop_internal(t_event);
#else
    return tee_timer_event_stop(t_event);
#endif
}

timer_event *SRE_TimerEventCreate(sw_timer_event_handler handler, int32_t timer_class, void *priv_data)
{
#ifndef CONFIG_OFF_DRV_TIMER
    return timer_event_create_internal(handler, timer_class, priv_data);
#else
    return tee_timer_event_create(handler, timer_class, priv_data);
#endif
}

uint32_t SRE_TimerEventDestroy(timer_event *t_event)
{
#ifndef CONFIG_OFF_DRV_TIMER
    return timer_event_destroy_internal(t_event);
#else
    return tee_timer_event_destroy(t_event);
#endif
}

void SRE_DelayMs(uint32_t delay)
{
    delay_ms(delay);
}

void SRE_DelayUs(uint32_t delay)
{
    delay_us(delay);
}

uint64_t SRE_ReadTimestamp(void)
{
    return read_time_stamp();
}

void release_timer_event(const TEE_UUID *uuid)
{
#ifndef CONFIG_OFF_DRV_TIMER
    release_timer_event_internal(uuid);
#else
    (void)uuid;
#endif
}

__attribute__((visibility("default"))) int set_ta_timer_permission(const TEE_UUID *uuid,
                                                                   uint64_t permission)
{
#ifdef CONFIG_OFF_DRV_TIMER
    (void)uuid;
    (void)permission;
    return 0;
#else
    return set_ta_timer_permission_internal(uuid, permission);
#endif
}
#endif /* CONFIG_TIMER_DISABLE */

#if (defined CONFIG_RTC_TIMER) && (!defined CONFIG_TIMER_DISABLE)
TEE_Result TEE_EXT_CreateTimer(uint32_t time_seconds, TEE_timer_property *timer_property)
{
    return tee_ext_create_timer(time_seconds, timer_property);
}

TEE_Result TEE_EXT_DestoryTimer(TEE_timer_property *timer_property)
{
    return tee_ext_destory_timer(timer_property);
}

TEE_Result TEE_EXT_GetTimerExpire(TEE_timer_property *timer_property, uint32_t *time_seconds)
{
    return tee_ext_get_timer_expire(timer_property, time_seconds);
}

TEE_Result TEE_EXT_GetTimerRemain(TEE_timer_property *timer_property, uint32_t *time_seconds)
{
    return tee_ext_get_timer_remain(timer_property, time_seconds);
}

__attribute__((visibility("default"))) UINT32 __get_secure_rtc_time(void)
{
    return get_secure_rtc_time();
}

UINT32 __sre_get_rtc_time(void)
{
    return get_secure_rtc_time();
}
#else
TEE_Result TEE_EXT_CreateTimer(uint32_t time_seconds, TEE_timer_property *timer_property)
{
    (void)time_seconds;
    (void)timer_property;
    return TMR_ERR;
}

TEE_Result TEE_EXT_DestoryTimer(TEE_timer_property *timer_property)
{
    (void)timer_property;
    return TMR_ERR;
}

TEE_Result TEE_EXT_GetTimerExpire(TEE_timer_property *timer_property, uint32_t *time_seconds)
{
    (void)timer_property;
    (void)time_seconds;
    return TMR_ERR;
}

TEE_Result TEE_EXT_GetTimerRemain(TEE_timer_property *timer_property, uint32_t *time_seconds)
{
    (void)timer_property;
    (void)time_seconds;
    return TMR_ERR;
}

__attribute__((visibility("default"))) UINT32 __get_secure_rtc_time(void)
{
    return TMR_ERR;
}

UINT32 __sre_get_rtc_time(void)
{
    return TMR_ERR;
}
#endif
