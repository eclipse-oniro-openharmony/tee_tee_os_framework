/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: rtc timer function
 * Create: 2022-04-22
 */
#ifndef LIBTIMER_TIMER_RTC_H
#define LIBTIMER_TIMER_RTC_H

uint32_t __sre_get_rtc_time(void);
uint32_t __get_secure_rtc_time(void);
uint32_t tee_get_secure_rtc_time(void);

TEE_Result tee_ext_create_timer(uint32_t time_seconds, const TEE_timer_property *timer_property);
TEE_Result tee_ext_destory_timer(const TEE_timer_property *timer_property);
TEE_Result tee_ext_get_timer_expire(const TEE_timer_property *timer_property, uint32_t *time_seconds);
TEE_Result tee_ext_get_timer_remain(const TEE_timer_property *timer_property, uint32_t *time_seconds);

TEE_Result TEE_EXT_CreateTimer(uint32_t time_seconds, TEE_timer_property *timer_property);
TEE_Result TEE_EXT_DestoryTimer(TEE_timer_property *timer_property);
TEE_Result TEE_EXT_GetTimerExpire(TEE_timer_property *timer_property, uint32_t *time_seconds);
TEE_Result TEE_EXT_GetTimerRemain(TEE_timer_property *timer_property, uint32_t *time_seconds);

#endif