/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: rtc timer related functions defined in this file.
 * Author: zhangdeyao zhangdeyao@huawei.com
 * Create: 2020-09-07
 */
#include "mtee_rtc.h"
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <memory.h>
#include <securec.h>
#include <tee_defines.h>
#include <hmlog.h>
#include "timer_types.h"
#include "pmic_wrap_read.h"

int32_t g_rtc_base;

/*
 * rtc_tm_to_time64 - Converts rtc_time to time64_t.
 * Convert Gregorian date to seconds since 01-01-1970 00:00:00.
 */
uint64_t rtc_tm_to_time64(const struct rtc_time *tm)
{
    if (tm == NULL) {
        hm_error("tm to time64: invalid params\n");
        return 0;
    }

    int32_t year = tm->tm_year + RTC_YEAR_BASE;
    int32_t mon  = tm->tm_mon + RTC_DEFAULT_MTH;
    int32_t day  = tm->tm_mday;
    int32_t hour = tm->tm_hour;
    int32_t min  = tm->tm_min;
    int32_t sec  = tm->tm_sec;

    /* 1..12 -> 11,12,1..10 */
    if ((mon -= 2) <= 0) {
        mon += MONTH_PER_YEAR;    /* Puts Feb last since it has leap day */
        year -= 1;
    }

    return ((((uint64_t)(year / LEAP_PARAM1 - year / LEAP_PARAM2 + year / LEAP_PARAM3 +
                         LEAP_MONTHS * mon / MONTH_PER_YEAR + day) + year * DAY_PER_YEAR -
                         LEAP_DAYS) * HOUR_PER_DAY + hour) * MIN_PER_HOUR + min) * SEC_PER_MIN + sec;
}

static inline bool is_leap_year(uint32_t year)
{
    return (!(year % LEAP_PARAM1) && (year % LEAP_PARAM2)) || !(year % LEAP_PARAM3);
}

/*
 * The number of days in the month.
 */
int32_t rtc_month_days(uint32_t month, uint32_t year)
{
    /* days per month during a year */
    unsigned char rtc_days_in_month[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    return rtc_days_in_month[month] + (is_leap_year(year) && month == 1);
}

/*
 * Does the rtc_time represent a valid date/time?
 */
static int32_t rtc_valid_tm(const struct rtc_time *tm)
{
    if (tm == NULL) {
        hm_error("valid tm: invalid params\n");
        return TMR_DRV_ERROR;
    }

    if (tm->tm_year < YEAR_BASE ||
        ((unsigned)tm->tm_mon) >= MONTH_PER_YEAR ||
        tm->tm_mday < MONTH_BASE ||
        tm->tm_mday > rtc_month_days(tm->tm_mon, tm->tm_year + RTC_YEAR_BASE) ||
        ((unsigned)tm->tm_hour) >= HOUR_PER_DAY ||
        ((unsigned)tm->tm_min) >= MIN_PER_HOUR ||
        ((unsigned)tm->tm_sec) >= SEC_PER_MIN)
        return TMR_DRV_ERROR;

    return TMR_DRV_SUCCESS;
}

 /*
  * MTK RTC Basic
  */
uint16_t rtc_read(uint16_t addr)
{
    uint32_t rdata = 0;
    int32_t ret;

    ret = pwrap_read((uint32_t) (g_rtc_base + addr), &rdata);
    if (ret != TMR_DRV_SUCCESS)
        hm_error("rtc read failed\n");

    return (uint16_t)rdata;
}

static void rtc_get_tick(struct rtc_time *tm)
{
    tm->tm_sec  = rtc_read(RTC_TC_SEC_SEC);
    tm->tm_min  = rtc_read(RTC_TC_MIN_SEC);
    tm->tm_hour = rtc_read(RTC_TC_HOU_SEC);
    tm->tm_mday = rtc_read(RTC_TC_DOM_SEC);
    tm->tm_mon  = rtc_read(RTC_TC_MTH_SEC);
    tm->tm_year = rtc_read(RTC_TC_YEA_SEC);
}

void hal_rtc_get_tick_time(struct rtc_time *tm)
{
    rtc_get_tick(tm);

    if (rtc_read(RTC_TC_SEC_SEC) < tm->tm_sec)    /* SEC has carried */
        rtc_get_tick(tm);
}

static int32_t rtc_ops_read_time(struct rtc_time *tm)
{
    uint64_t time;

    if (tm == NULL) {
        hm_error("read_time: invalid params\n");
        return TMR_DRV_ERROR;
    }

    hal_rtc_get_tick_time(tm);

    tm->tm_year += RTC_MIN_YEAR_OFFSET;
    tm->tm_mon--;

    time = rtc_tm_to_time64(tm);
    if (time == 0) {
        hm_error("invalid timestampe\n");
        return TMR_DRV_ERROR;
    }

    tm->tm_wday = (time / SEC_PER_DAY + THURSDAY_IN_WEEK) % DAY_PER_WEEK;    /* 1970/01/01 is Thursday */

    return TMR_DRV_SUCCESS;
}

/*
 * MTK RTC Tick
 * Define : kernel-4.4/drivers/rtc/rtc-lib.c
 */
int32_t rtc_read_time(struct rtc_time *tm)
{
    int32_t ret;
    errno_t ret_s;

    if (tm == NULL) {
        hm_error("rtc read time: invalid params\n");
        return TMR_DRV_ERROR;
    }

    ret_s = memset_s(tm, sizeof(*tm), 0, sizeof(*tm));
    if (ret_s != EOK) {
        hm_error("memset failed\n");
        return TMR_DRV_ERROR;
    }

    ret = rtc_ops_read_time(tm);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("rtc read time: fail to read: %d\n", ret);
        return ret;
    }

    ret = rtc_valid_tm(tm);
    if (ret != TMR_DRV_SUCCESS)
        hm_error("rtc read time: rtc_time isn't valid\n");

    tm->tm_year += RTC_YEAR_BASE;
    tm->tm_mon++;

    return ret;
}

void rtc_init(void)
{
    struct rtc_time tm;
    int32_t ret;

    g_rtc_base = RTC_M_BASE;

    ret = rtc_read_time(&tm);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("RTC init failed\n");
        return;
    }

    hm_debug("rtc_read_time done\n");
    hm_debug("Current RTC time:[%d/%d/%d %d:%d:%d]\n",
             tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}
