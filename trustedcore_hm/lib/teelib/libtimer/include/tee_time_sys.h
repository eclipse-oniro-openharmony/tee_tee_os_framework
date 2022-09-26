/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: rtc timer function
 * Create: 2022-04-22
 */
#ifndef LIBTIMER_TEE_TIME_SYS_H
#define LIBTIMER_TEE_TIME_SYS_H
#include <tee_time_defines.h>

uint64_t tee_read_time_stamp(void);
void get_sys_date_time(tee_date_time_kernel *time_date);
void gen_sys_date_time(uint32_t secs, tee_date_time_kernel *date_time);
struct tm *__localtime_r(const time_t *restrict, struct tm *restrict);
uint32_t adjust_sys_time(const struct tee_time_t *time);
int set_ta_timer_permission(const TEE_UUID *uuid, uint64_t permission);
void release_timer_event(const TEE_UUID *uuid);
int hm_timer_init(void);
#endif
