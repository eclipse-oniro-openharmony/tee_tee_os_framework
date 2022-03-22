/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Sleep function for timer
 * Create: 2019-08-20
 */
#include "sleep.h"
#include <timer.h>

unsigned int sleep_internal(unsigned int seconds)
{
    struct timespec tv;

    tv.tv_nsec = 0;
    tv.tv_sec  = seconds;

    if (nanosleep(&tv, &tv) != TMR_OK)
        return tv.tv_sec;

    return TMR_OK;
}
