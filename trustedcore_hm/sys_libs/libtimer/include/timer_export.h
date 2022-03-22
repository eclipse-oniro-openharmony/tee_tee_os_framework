/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file about timer export.
 * Create: 2019-08-20
 */

#ifndef SYS_LIBS_LIBTIMER_A32_TIMER_EXPORT_H
#define SYS_LIBS_LIBTIMER_A32_TIMER_EXPORT_H

#include <tee_defines.h>
#include <sys_timer.h>

timer_event *__SRE_TimerEventCreate(sw_timer_event_handler handler, int32_t timer_class, void *priv_data);
UINT32 __SRE_TimerEventDestroy(timer_event *t_event);
UINT32 __SRE_TimerEventStart(timer_event *t_event, timeval_t *time);
UINT32 __SRE_TimerEventStop(timer_event *t_event);
UINT32 __SRE_TimerCheck(timer_notify_data_kernel *timer_data);
UINT64 __SRE_TimerGetExpire(timer_event *t_event);
UINT64 __SRE_ReadTimestamp(void);
uint64_t SRE_ReadTimestamp(void);
UINT32 __SRE_SwMsleep(uint32_t msec);
void SRE_DelayMs(uint32_t delay);
void SRE_DelayUs(uint32_t delay);
void __get_startup_time(tee_time_kernel *time, uint32_t *rtc_time);
UINT32 __sre_get_rtc_time(void);
UINT32 __get_secure_rtc_time(void);
void __get_sys_date_time(tee_date_time_kernel *time_date);
void __gen_sys_date_time(uint32_t secs, tee_date_time_kernel *date_time);
UINT32 __adjust_sys_time(const tee_time_kernel *time);
void __init_startup_time_kernel(uint32_t rtc_time);
TEE_Result TEE_ANTI_ROOT_DestoryTimer(void);
void tee_timer_drv_init(void);
INT32 hm_timer_init(void);
struct tm *__localtime_r(const time_t *restrict, struct tm *restrict);
int set_ta_timer_permission(const TEE_UUID *uuid, uint64_t permission);

#endif /* SYS_LIBS_LIBTIMER_A32_TIMER_EXPORT_H */
