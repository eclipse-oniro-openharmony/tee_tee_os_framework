/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Header file for timer common.
 * Create: 2021-05-27
 */

#ifndef RTC_TIMER_DRIVER_RTC_TIMER_PM_H
#define RTC_TIMER_DRIVER_RTC_TIMER_PM_H

#include <stdint.h>

int32_t rtc_timer_suspend(void);
int32_t rtc_timer_resume(void);

#define TIMER_SUSPEND_S3 0
#define TIMER_SUSPEND_S4 1
#define TIMER_RESUME_S3  0
#define TIMER_RESUME_S4  1

#endif /* RTC_TIMER_DRIVER_RTC_TIMER_PM_H */
