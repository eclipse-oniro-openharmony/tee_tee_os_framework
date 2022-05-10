/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: Header of legacy timer api
 * Create: 2022-04-22
 */

#ifndef SYS_LIBS_LIBTIMER_LEGACY_H
#define SYS_LIBS_LIBTIMER_LEGACY_H

#include <stdint.h>

uint64_t SRE_ReadTimestamp(void);
uint64_t __SRE_ReadTimestamp(void);
void __get_sys_date_time(tee_date_time_kernel *time_date);
void __gen_sys_date_time(const uint32_t rtc_time, struct tee_date_t *time);

uint32_t __SRE_SwMsleep(uint32_t msec);
uint32_t SRE_SwMsleep(uint32_t msec);
uint32_t SRE_SwUsleep(uint32_t microsecond);
void SRE_DelayMs(uint32_t delay);
void SRE_DelayUs(uint32_t delay);

timer_event *SRE_TimerEventCreate(sw_timer_event_handler handler, int32_t timer_class, void *priv_data);
uint32_t SRE_TimerEventDestroy(timer_event *t_event);
uint32_t SRE_TimerEventStart(timer_event *t_event, timeval_t *time);
uint32_t SRE_TimerEventStop(timer_event *t_event);

timer_event *__SRE_TimerEventCreate(sw_timer_event_handler handler, int32_t timer_class, void *priv_data);
uint32_t __SRE_TimerEventDestroy(timer_event *t_event);
uint32_t __SRE_TimerEventStart(timer_event *t_event, timeval_t *time);
uint32_t __SRE_TimerEventStop(timer_event *t_event);
uint32_t __SRE_TimerCheck(timer_notify_data_kernel *timer_data);
uint64_t __SRE_TimerGetExpire(timer_event *t_event);

TEE_Result TEE_ANTI_ROOT_CreateTimer(uint32_t time_seconds);
TEE_Result TEE_ANTI_ROOT_DestoryTimer(void);

#endif /* SYS_LIBS_LIBTIMER_LEGACY_H */
