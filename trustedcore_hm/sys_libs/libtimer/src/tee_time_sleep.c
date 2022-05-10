/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: sleep time api define in this file.
 * Create: 2022-04-22
 */
#include <sys_timer.h>
#include <hmlog.h>
#include <tee_time_adapt.h>
#include <time.h>
#include <tee_time_event.h>

#define MAX_SECONDS  0xFFFFFFFF

int32_t nanosleep(const struct timespec *req, struct timespec *rem)
{
    uint32_t mill_second;
    uint32_t ret;

    if ((req == NULL) || (req->tv_nsec >= NS_PER_SECONDS) || (req->tv_nsec < 0) || (req->tv_sec < 0) ||
        ((req->tv_sec + 1) >= (long)(MAX_SECONDS / MS_PER_SECONDS)))
        return TMR_ERR;

    mill_second = (uint32_t)((req->tv_sec * MS_PER_SECONDS) + (req->tv_nsec / NS_PER_MSEC));
    struct timer_ops_t *time_ops = NULL;
    time_ops = get_time_ops();
    if (time_ops == NULL)
        return TMR_ERR;

    ret = time_ops->sleep(mill_second);
    if (ret != TMR_OK)
        return TMR_ERR;

    if (rem != NULL) {
        rem->tv_sec  = 0;
        rem->tv_nsec = 0;
    }

    return TMR_OK;
}

uint32_t sleep(uint32_t seconds)
{
    struct timespec tv;
    tv.tv_nsec = 0;
    tv.tv_sec  = seconds;

    if (nanosleep(&tv, &tv) != TMR_OK)
        return tv.tv_sec;

    return TMR_OK;
}

void delay_us(uint32_t microseconds)
{
    uint64_t counts = 0;
    uint64_t time_stamp;
    uint64_t start_time;
    uint64_t cur_time;

    if (microseconds > US_PER_SECONDS) {
        hm_error("The value of microseconds is extend the range\n");
        return;
    }

    struct timer_ops_t *time_ops = NULL;
    time_ops = get_time_ops();
    if (time_ops == NULL)
        return;

    time_stamp = time_ops->read_time_stamp();
    while (counts < microseconds) {
        start_time = (uint64_t)UPPER_32_BITS(time_stamp) * US_PER_SECONDS + LOWER_32_BITS(time_stamp) / NS_PER_USEC;
        time_stamp = time_ops->read_time_stamp();
        cur_time = (uint64_t)UPPER_32_BITS(time_stamp) * US_PER_SECONDS + LOWER_32_BITS(time_stamp) / NS_PER_USEC;
        counts += cur_time - start_time;
    }
}

void delay_ms(uint32_t msec)
{
    delay_us(msec * US_PER_MSEC);
}

uint32_t tee_msleep(uint32_t msec)
{
    if (msec > MS_PER_SECONDS) {
        hm_error("The value of microseconds is extend the range\n");
        return TMR_ERR;
    }

    delay_ms(msec);
    return TMR_OK;
}
