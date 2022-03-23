/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Nanosleep function for timer
 * Create: 2019-08-20
 */
#include "nanosleep.h"
#include <stdio.h>
#include <tee_defines.h>
#include <timer.h>
#include "tee_time_api.h"

int nanosleep_internal(const struct timespec *req, struct timespec *rem)
{
    uint32_t mill_second;
    TEE_Result ret;

    if ((req == NULL) || (req->tv_nsec >= NS_PER_SECONDS) || (req->tv_nsec < 0) || (req->tv_sec < 0) ||
        ((req->tv_sec + 1) >= (long)(0xffffffff / MS_PER_SECONDS)))
        return TMR_ERR;

    mill_second = (uint32_t)((req->tv_sec * MS_PER_SECONDS) + (req->tv_nsec / NS_PER_MSEC));
    ret         = TEE_Wait(mill_second);
    if (ret != TEE_SUCCESS)
        return TMR_ERR;

    if (rem != NULL) {
        rem->tv_sec  = 0;
        rem->tv_nsec = 0;
    }

    return TMR_OK;
}
