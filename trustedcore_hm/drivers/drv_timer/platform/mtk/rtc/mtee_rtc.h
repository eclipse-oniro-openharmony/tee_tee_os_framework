/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: rtc timer related functions defined in this file.
 * Author: zhangdeyao zhangdeyao@huawei.com
 * Create: 2020-09-07
 */
#ifndef DRVTIMER_RTC_MTEE_RTC_H
#define DRVTIMER_RTC_MTEE_RTC_H

#include <stdint.h>
#include "timer_rtc.h"


/* we map HW YEA 0 (2000) to 1968 not 1970 because 2000 is the leap year */
#define RTC_MIN_YEAR        1968
#define RTC_NUM_YEARS       128

/*
 * Reset to default date if RTC time is over 2038/1/19 3:14:7
 * Year (YEA)        : 1970 ~ 2037
 * Month (MTH)       : 1 ~ 12
 * Day of Month (DOM): 1 ~ 31
 */
#define RTC_YEAR_BASE          1900
#define RTC_DEFAULT_YEA        2020
#define RTC_DEFAULT_MTH        1
#define RTC_DEFAULT_DOM        1
#define RTC_MIN_YEAR_OFFSET    (RTC_MIN_YEAR - RTC_YEAR_BASE)

#define MONTH_BASE          1
#define YEAR_BASE           70
#define MONTH_PER_YEAR      12
#define DAY_PER_YEAR        365
#define DAY_PER_WEEK        7
#define HOUR_PER_DAY        24
#define MIN_PER_HOUR        60
#define SEC_PER_MIN         60
#define SEC_PER_DAY         86400
#define THURSDAY_IN_WEEK    4
#define LEAP_PARAM1         4
#define LEAP_PARAM2         100
#define LEAP_PARAM3         400
#define LEAP_MONTHS         367
#define LEAP_DAYS           719499

#define RTC_TC_SEC_SEC      0x8
#define RTC_TC_MIN_SEC      0xa
#define RTC_TC_HOU_SEC      0xc
#define RTC_TC_DOM_SEC      0xe
#define RTC_TC_DOW_SEC      0x10
#define RTC_TC_MTH_SEC      0x12
#define RTC_TC_YEA_SEC      0x14
#define RTC_M_BASE          0x600

uint64_t rtc_tm_to_time64(const struct rtc_time *tm);
int32_t rtc_read_time(struct rtc_time *tm);
void rtc_init(void);

#endif
