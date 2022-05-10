/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for timer_sys
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_PLATFORM_TIMER_SYS_H
#define DRV_TIMER_PLATFORM_TIMER_SYS_H

#include <sys_timer.h>

#define MIN_CLOCK_CYCLES    1
/*
 * 1000 = 1024 + 8 - 32 = 2^10 + 2^3 - 2^5
 * Divide by 1000: x/1000 = x>>10 + 3*x>>17 + 9*x>>24
 * or y=x>>10, x/1000 = y+ (3*y)>>7 + (9*y) >> 14
 * Multiply by 1000: x*1000 = x<<10 + x<<3 - x<<5
 */
#define mul_by_1000(data)   (((data) << 10) + ((data) << 3) - ((data) << 5))
#define div_by_1024(data)   ((data) >> 10)
#define div_by_1000(data)   (((data) >> 10) + (((data) * 3) >> 17) - (((data) * 9) >> 24))
#define div_by_1000_1024(y) ((y) + ((3 * (y)) >> 7) + ((9 * (y)) >> 14))
#define get_time_value(time_high, time_low) (((uint64_t)(time_high) << 32) | (time_low))

void init_startup_time_kernel(uint32_t rtc_time);

void get_sys_startup_time(struct tee_time_t *time, uint32_t *rtc_time);

void get_sys_rtc_time_kernel(struct tee_time_t *time);

void get_sys_rtc_time_offset(struct tee_time_t *time);

void gen_sys_date_time(const uint32_t rtc_time, struct tee_date_t *time);

uint32_t drv_get_sys_date_time(struct tee_date_t *time_date);

uint32_t timer_clock_to_timeval(uint64_t clock_cycles, int32_t *seconds, int32_t *n_seconds);

uint32_t timer_timeval_to_clock(const timeval_t *time, int32_t timer_class, uint64_t *clock_cycles);

int64_t timer_value_add(const timeval_t *time_val_1, const timeval_t *time_val_2);

void timer_cpu_info_init(void);

int64_t timer_stamp_value_read(void);

void timer_free_running_value_set(void);

void set_timer_cycles_count_old_zero(void);

void timer_resume_stamp(timeval_t sleep_time_pc);

bool is_tick_timer(int32_t timer_class);
#endif
