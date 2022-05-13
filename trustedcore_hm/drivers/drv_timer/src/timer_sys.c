/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: timer system related functions defined in this file.
 * Create: 2019-08-20
 */
#include "timer_sys.h"
#include <securec.h>
#include <hmlog.h>
#include <limits.h>
#include "timer_event.h"
#include "timer_reg.h"
#include "timer_hw.h"
#include "sys_timer.h"
#include "timer_types.h"
static struct tee_time_t g_startup_sys_time;
static struct tee_time_t g_kernel_time_offset;
static uint32_t g_startup_rtc_time;
static struct sw_timer_info  g_sw_timer_info;

static const uint32_t g_mon_lengths[][MONSPERYEAR] = {
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};
static const uint32_t g_year_lengths[] = { DAYSPERNYEAR, DAYSPERLYEAR };
#define leap_days_get(year) (((year) / 4) - ((year) / 100) + ((year) / 400))
#define INVALID_TIME_STAMP 0

static void get_system_time(struct tee_time_t *time)
{
    uint64_t time_value;

    time_value = (uint64_t)timer_stamp_value_read();
    time->seconds = (int32_t)UPPER_32_BITS(time_value);
    time->millis = (int32_t)LOWER_32_BITS(time_value) / NS_PER_MSEC;
}

void adjust_sys_time(const struct tee_time_t *time)
{
    if (time == NULL) {
        hm_error("time is NULL\n");
        return;
    }

    if ((time->seconds < 0) || (time->millis < 0) || (time->millis >= MS_PER_SECONDS)) {
        hm_error("time params is error, seconds = %d, millis = %d\n", time->seconds, time->millis);
        return;
    }

    get_system_time(&g_startup_sys_time);
    if (time->seconds < g_startup_sys_time.seconds) {
        hm_error("invalid time value, please check\n");
        return;
    }

    if (g_startup_sys_time.millis < time->millis) {
        g_kernel_time_offset.seconds = time->seconds - g_startup_sys_time.seconds;
        g_kernel_time_offset.millis = time->millis - g_startup_sys_time.millis;
    } else {
        g_kernel_time_offset.seconds = time->seconds - g_startup_sys_time.seconds - 1;
        g_kernel_time_offset.millis = time->millis + MS_PER_SECONDS - g_startup_sys_time.millis;
    }
}

void init_startup_time_kernel(uint32_t rtc_time)
{
    get_system_time(&g_startup_sys_time);
    g_startup_rtc_time = rtc_time;
}

void get_sys_startup_time(struct tee_time_t *time, uint32_t *rtc_time)
{
    errno_t ret_s;

    if ((time == NULL) || (rtc_time == NULL)) {
        hm_warn("get startup time failed, null pointer detected\n");
        return;
    }

    *rtc_time = g_startup_rtc_time;
    ret_s = memcpy_s(time, sizeof(*time), &g_startup_sys_time, sizeof(g_startup_sys_time));
    if (ret_s != EOK) {
        hm_error("memcpy failed!\n");
        return;
    }
}

void get_sys_rtc_time_kernel(struct tee_time_t *time)
{
    struct tee_time_t tmp_time;

    if (time == NULL) {
        hm_error("time is NULL!\n");
        return;
    }

    get_system_time(&tmp_time);
    tmp_time.millis += g_kernel_time_offset.millis;
    tmp_time.seconds += g_kernel_time_offset.seconds;

    while (tmp_time.millis >= MS_PER_SECONDS) {
        tmp_time.millis -= MS_PER_SECONDS;
        tmp_time.seconds += 1;
    }

    time->seconds = tmp_time.seconds;
    time->millis = tmp_time.millis;
}

void get_sys_rtc_time_offset(struct tee_time_t *time)
{
    if (time == NULL) {
        hm_error("time is NULL!\n");
        return;
    }

    time->seconds = g_kernel_time_offset.seconds;
    time->millis = g_kernel_time_offset.millis;
}

static uint32_t increment_overflow(uint32_t *year, uint32_t carry)
{
    if (carry > (UINT_MAX - *year)) {
        hm_error("overflow, year=%u, carry=%u\n", *year, carry);
        return TMR_DRV_ERROR;
    }

    *year += carry;

    return TMR_DRV_SUCCESS;
}

static uint32_t is_leap_year(uint32_t year)
{
    if (((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0))
        return 1;

    return 0;
}

static uint32_t get_days_and_year(uint32_t *tdays, uint32_t *year)
{
    uint32_t ret;
    uint32_t new_year;
    uint32_t carry_over;
    uint32_t leap_days;

    while (*tdays >= g_year_lengths[is_leap_year(*year)]) {
        carry_over = *tdays / DAYSPERLYEAR;
        if (carry_over == 0)
            carry_over = 1;

        new_year = *year;
        ret = increment_overflow(&new_year, carry_over);
        if (ret != TMR_DRV_SUCCESS)
            return TMR_DRV_ERROR;

        leap_days = leap_days_get(new_year - 1) - leap_days_get(*year - 1);
        if (new_year < *year)
            return TMR_DRV_ERROR;
        *tdays -= (new_year - *year) * DAYSPERNYEAR;
        *tdays -= leap_days;
        *year = new_year;
    }

    return TMR_DRV_SUCCESS;
}

void gen_sys_date_time(const uint32_t rtc_time, struct tee_date_t *time)
{
    uint32_t seconds;
    uint32_t tdays;
    uint32_t idays;
    uint32_t rem_secs;
    uint32_t year;
    const uint32_t *ip = NULL;
    uint32_t ret;

    if (time == NULL) {
        hm_error("Error:time is null\n");
        return;
    }

    seconds = rtc_time;
    year = EPOCH_YEAR;
    tdays = seconds / SECSPERDAY;
    rem_secs = seconds - tdays * SECSPERDAY;

    ret = get_days_and_year(&tdays, &year);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("failed to get the day and year\n");
        return;
    }

    idays = tdays;
    time->year = (int32_t)year;
    time->hour = (int32_t)(rem_secs / SECSPERHOUR);
    rem_secs %= SECSPERHOUR;
    time->min = (int32_t)(rem_secs / SECSPERMIN);
    time->seconds = (int32_t)(rem_secs % SECSPERMIN);
    ip = g_mon_lengths[is_leap_year(year)];
    time->month = 0;

    for (int i = 0; i < MONSPERYEAR; i++) {
        time->month++;
        if (idays < ip[i])
            break;
        idays -= ip[i];
    }
    time->day = (int32_t)(idays + 1);
}

uint32_t drv_get_sys_date_time(struct tee_date_t *time_date)
{
    struct tee_time_t time;

    if (time_date == NULL) {
        hm_error("time date is null!\n");
        return TMR_DRV_ERROR;
    }

    get_sys_rtc_time_kernel(&time);
    if ((time.seconds < 0) || (time.millis < 0) || (time.millis >= MS_PER_SECONDS)) {
        hm_error("bad timer read, execution shouldn't reach here\n");
        return TMR_DRV_ERROR;
    }

    time_date->seconds = time.seconds + TIME_ZONE_EIGHT * SECSPERHOUR;
    if (time_date->seconds < 0) {
        hm_error("bad timer read\n");
        time_date->seconds = 0;
        return TMR_DRV_ERROR;
    }

    time_date->millis = time.millis;
    gen_sys_date_time(time_date->seconds, time_date);

    return TMR_DRV_SUCCESS;
}

/*
 * This function is used in tee_log.c for print time in log.
 * Keep consistent with libtimer.
 */
void get_sys_date_time(tee_date_time_kernel *time_date)
{
    uint32_t ret;
    if (time_date == NULL) {
        hm_error("time date is null!\n");
        return;
    }

    ret = drv_get_sys_date_time((struct tee_date_t *)time_date);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("Failed to get sys date time\n");
        errno_t ret_s = memset_s(time_date, sizeof(*time_date), 0, sizeof(*time_date));
        if (ret_s != EOK)
            hm_error("memory set failed!\n");
    }
}

uint32_t timer_clock_to_timeval(uint64_t clock_cycles, int32_t *seconds, int32_t *n_seconds)
{
    timeval_t time;
    uint64_t tmp_nsecs;
    uint64_t tmp_secs;
    uint64_t tmp_usecs;
    uint64_t tmp_calc;
    uint64_t usecs;

    if (seconds == NULL || n_seconds == NULL) {
        hm_error("invalid param\n");
        return TMR_DRV_ERROR;
    }

    if (clock_cycles > FREE_TIMER_COUNT_MAX) {
        hm_error("clock cycles is greater than free count max\n");
        return TMR_DRV_ERROR;
    }

    usecs = (clock_cycles * NS_PER_MSEC) / TIMER_CLK_FREQ;
    tmp_secs = usecs;
    tmp_secs = div_by_1024(tmp_secs);
    if (tmp_secs > (UINT64_MAX / 9)) { /* 9 for overflow */
        hm_error("tmp secs is greater than UINT64_MAX/9\n");
        return TMR_DRV_ERROR;
    }

    tmp_secs = div_by_1000_1024(tmp_secs);
    tmp_secs = div_by_1024(tmp_secs);
    tmp_secs = div_by_1000_1024(tmp_secs);
    /*
     * Multiply number of seconds with 10^6 to convert it to number of
     * clock_cycles and then subtract it from the total number of
     * clock_cycles to obtain the number of microseconds
     */
    tmp_calc = mul_by_1000(tmp_secs);
    tmp_calc = mul_by_1000(tmp_calc);
    tmp_usecs = usecs - tmp_calc;
    tmp_nsecs = mul_by_1000(tmp_usecs);
    while (tmp_nsecs >= NS_PER_SECONDS) {
        tmp_nsecs -= NS_PER_SECONDS;
        tmp_secs += 1;
    }

    time.tval.sec = (int32_t)tmp_secs;
    time.tval.nsec = (int32_t)tmp_nsecs;
    *seconds = time.tval.sec;
    *n_seconds = time.tval.nsec;

    return TMR_DRV_SUCCESS;
}

bool is_tick_timer(int32_t timer_class)
{
#ifndef SOFT_RTC_TICK
    if ((timer_class == TIMER_GENERIC) || (timer_class == TIMER_CLASSIC))
#else
    if ((timer_class == TIMER_GENERIC) || (timer_class == TIMER_CLASSIC) || timer_class == TIMER_RTC)
#endif
        return true;
    else
        return false;
}

uint32_t timer_timeval_to_clock(const timeval_t *time, int32_t timer_class, uint64_t *clock_cycles)
{
    uint64_t useconds;
    uint64_t tmp_sec;
    uint64_t tmp_nsec;
    if (time == NULL || clock_cycles == NULL) {
        hm_error("time params error\n");
        return TMR_DRV_ERROR;
    }

    if ((time->tval.sec < 0) || (time->tval.nsec < 0)) {
        hm_error("time params error, time->tval.sec = %d, time->tval.nsec = %d\n", time->tval.sec, time->tval.nsec);
        return TMR_DRV_ERROR;
    }

    tmp_sec = (uint64_t)(time->tval.sec);
    if (is_tick_timer(timer_class)) {
        if (tmp_sec > 0) { /* seconds to us */
            tmp_sec = mul_by_1000(tmp_sec);
            tmp_sec = mul_by_1000(tmp_sec);
        }

        tmp_nsec = (uint64_t)(time->tval.nsec);
        tmp_nsec = div_by_1024(tmp_nsec);
        tmp_nsec = div_by_1000_1024(tmp_nsec);
        useconds = tmp_nsec + tmp_sec;
        *clock_cycles = ((uint64_t)useconds * TIMER_CLK_FREQ) / NS_PER_MSEC;
        /* Minimum clock cycles to be 1 clock period */
        if (*clock_cycles < MIN_CLOCK_CYCLES)
            *clock_cycles = MIN_CLOCK_CYCLES;
#ifndef SOFT_RTC_TICK
    } else if (timer_class == TIMER_RTC) {
        *clock_cycles = tmp_sec;
#endif
    } else {
        hm_error("timer class %d is not supportted!\n", timer_class);
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

int64_t timer_value_add(const timeval_t *time_val_1, const timeval_t *time_val_2)
{
    timeval_t time_val_sum;

    if (time_val_1 == NULL || time_val_2 == NULL) {
        hm_error("invlid param\n");
        return TIMEVAL_MAX;
    }

    if ((time_val_1->tval64 > 0 && time_val_2->tval64 > 0 && INT64_MAX - time_val_1->tval64 < time_val_2->tval64) ||
        (time_val_1->tval64 < 0 && time_val_2->tval64 < 0 && INT64_MIN - time_val_1->tval64 > time_val_2->tval64)) {
        hm_error("Time value add result overflow!\n");
        return TIMEVAL_MAX;
    }

    if ((time_val_1->tval.nsec >= NS_PER_SECONDS) || (time_val_2->tval.nsec >= NS_PER_SECONDS)) {
        hm_warn("timer value add:invalid nsec value\n");
        time_val_sum.tval.sec = time_val_1->tval.sec + time_val_2->tval.sec;
        time_val_sum.tval.nsec = 0;
    } else {
        time_val_sum.tval64 = time_val_1->tval64 + time_val_2->tval64;
        if (time_val_sum.tval.nsec > (NS_PER_SECONDS - 1)) {
            time_val_sum.tval.nsec -= NS_PER_SECONDS;
            time_val_sum.tval.sec += 1;
        }
    }

    return time_val_sum.tval64;
}

void timer_cpu_info_init(void)
{
#ifdef TIMER_EVENT_SUPPORT
    int32_t iter;
    struct timer_cpu_info *timer_cpu_info_tmp = get_timer_cpu_info();
    if (timer_cpu_info_tmp == NULL) {
        hm_warn("timer_cpu_info invalid\n");
        return;
    }

    for (iter = 0; iter < MAX_NUM_OF_TIMERS; iter++) {
        timer_cpu_info_tmp->expires_next[iter].tval64 = TIMEVAL_MAX;
        timer_cpu_info_tmp->clock_info[iter].cpu_info = timer_cpu_info_tmp;
        timer_cpu_info_tmp->clock_info[iter].clock_id = iter;
        dlist_init(&timer_cpu_info_tmp->clock_info[iter].active);
        dlist_init(&timer_cpu_info_tmp->clock_info[iter].avail);
    }
#endif

    g_sw_timer_info.sw_timestamp.tval64 = 0;
    g_sw_timer_info.abs_cycles_count = 0;
    g_sw_timer_info.cycles_count_new = 0;
    g_sw_timer_info.cycles_count_old = 0;
}

int64_t timer_stamp_value_read(void)
{
    uint64_t tmp_cycles;
    int32_t sec_val;
    int32_t nsec_val;
    timeval_t tmp_timeval;
    uint32_t ret;

    g_sw_timer_info.cycles_count_new = timer_free_running_value_get();
    if (g_sw_timer_info.cycles_count_new < g_sw_timer_info.cycles_count_old) {
        tmp_cycles = TIMER_COUNT_MAX - g_sw_timer_info.cycles_count_old + g_sw_timer_info.cycles_count_new;
        g_sw_timer_info.cycles_count_old = TIMER_COUNT_MAX;
    } else {
        tmp_cycles = g_sw_timer_info.cycles_count_new - g_sw_timer_info.cycles_count_old;
        g_sw_timer_info.cycles_count_old = g_sw_timer_info.cycles_count_new;
    }

    g_sw_timer_info.abs_cycles_count += tmp_cycles;
    ret = timer_clock_to_timeval(tmp_cycles, &sec_val, &nsec_val);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("Failed to transform timer clock to timeval\n");
        return INVALID_TIME_STAMP;
    }

    tmp_timeval.tval.sec = sec_val;
    tmp_timeval.tval.nsec = nsec_val;
    g_sw_timer_info.sw_timestamp.tval64 = timer_value_add(&g_sw_timer_info.sw_timestamp, &tmp_timeval);

    return g_sw_timer_info.sw_timestamp.tval64;
}

#ifdef TIMER_S3_ADJUST_FREQ
void timer_resume_stamp(timeval_t sleep_time)
{
    /* add sleep time to system time */
    hm_debug("timer g_sw_timer_info.sw_timestamp.tval64 1 is %lld\n", g_sw_timer_info.sw_timestamp.tval64);
    g_sw_timer_info.sw_timestamp.tval64 = timer_value_add(&g_sw_timer_info.sw_timestamp, &sleep_time);
    hm_debug("timer g_sw_timer_info.sw_timestamp.tval64 2 is %lld\n", g_sw_timer_info.sw_timestamp.tval64);
}

void set_timer_cycles_count_old_zero(void)
{
    hm_debug("set_timer g_sw_timer_info.cycles_count_old 1 is %lld\n", g_sw_timer_info.cycles_count_old);
    g_sw_timer_info.cycles_count_old = 0;
    hm_debug("set_timer g_sw_timer_info.cycles_count_old 2 is %lld\n", g_sw_timer_info.cycles_count_old);
}
#endif

void timer_free_running_value_set(void)
{
    uint64_t tmp_cycles;
    int32_t sec_val;
    int32_t nsec_val;
    timeval_t tmp_timeval;
    uint32_t ret;

    g_sw_timer_info.cycles_count_new = TIMER_COUNT_MAX;
    tmp_cycles = g_sw_timer_info.cycles_count_new - g_sw_timer_info.cycles_count_old;
    g_sw_timer_info.abs_cycles_count += tmp_cycles;
    g_sw_timer_info.cycles_count_old = 0;

    ret = timer_clock_to_timeval(tmp_cycles, &sec_val, &nsec_val);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("Failed to transform timer clock to timeval when processing interrupt\n");
        return;
    }

    tmp_timeval.tval.sec = sec_val;
    tmp_timeval.tval.nsec = nsec_val;
    g_sw_timer_info.sw_timestamp.tval64 = timer_value_add(&g_sw_timer_info.sw_timestamp, &tmp_timeval);
}
