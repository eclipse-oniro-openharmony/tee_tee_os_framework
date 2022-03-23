/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee time api test
 * Author: Hisilicon
 * Created: 2020-05-05
 */

#include "tee_test_ta_time.h"
#include "tee_log.h"

static char *g_month_str[MONTH_PER_YEAR] = {
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
};

static void ta_test_time_to_date(TEE_Time *time, tee_date *date)
{
    unsigned int month[MONTH_PER_YEAR] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    unsigned int sec, day;
    int i;
    if (time == NULL || date == NULL) {
        return;
    }

    sec = time->seconds;
    date->year = 1970 + sec / SEC_PER_YEAR;  /* year start from 1970 */
    sec %= SEC_PER_YEAR;
    day = sec / SEC_PER_DAY;
    for (i = 0; i < MONTH_PER_YEAR && day >= month[i]; i++) {
        day -= month[i];
    }
    date->month = 1 + i;
    date->day = 1 + day;
    sec %= SEC_PER_DAY;
    date->hour = sec / SEC_PER_HOUR;
    sec %= SEC_PER_HOUR;
    date->min = sec / SEC_PER_MIN;
    date->sec = sec % SEC_PER_MIN;
    date->ms  = time->millis;
}

static TEE_Result ta_test_get_time(bool tee)
{
    tee_date date = {0};
    TEE_Time time = {
        .seconds = 0,
        .millis = 0,
    };

    if (tee) {
        TEE_GetSystemTime(&time);
    } else {
        TEE_GetREETime(&time);
    }
    ta_test_time_to_date(&time, &date);
    hi_tee_printf("TEE system time is %d:%d:%d:%d %s %d, %d, UTC since midnight on January 1, 1970, UTC\n",
                  date.hour, date.min, date.sec, date.ms, g_month_str[date.month - 1], date.day, date.year);

    return TEE_SUCCESS;
}

static TEE_Result ta_test_wait(unsigned int ms)
{
    TEE_Time time_start = {
        .seconds = 0,
        .millis = 0,
    };
    TEE_Time time_end = {
        .seconds = 0,
        .millis = 0,
    };
    int time_tmp;
    TEE_Result ret;

    TEE_GetSystemTime(&time_start);
    ret = TEE_Wait(ms);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_Wait %dms failed!\n", ms);
        return ret;
    }
    TEE_GetSystemTime(&time_end);

    time_tmp = (time_end.seconds - time_start.seconds) * 1000 + time_end.millis - time_start.millis; /* 1s, 1000ms */
    hi_tee_printf("The tee wait delay time is %dms\n", time_tmp);
    if (time_tmp - ms > ms / 10) { /* 10% */
        ret = TEE_ERROR_GENERIC;
    }
    return ret;
}

TEE_Result ta_test_time(unsigned int cmd, unsigned int ms)
{
    TEE_Result ret;

    switch (cmd) {
        case TEE_TIME_CMD_GET_TEE_TIME:
            ret = ta_test_get_time(true);
            break;
        case TEE_TIME_CMD_GET_REE_TIME:
            ret = ta_test_get_time(false);
            break;
        case TEE_TIME_CMD_WAIT:
            ret = ta_test_wait(ms);
            break;
        default:
            tloge("Invalid cmd[0x%X]!\n", cmd);
            ret = TEE_ERROR_INVALID_CMD;
            break;
    }

    return ret;
}
