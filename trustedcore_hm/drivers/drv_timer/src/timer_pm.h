/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for timer common.
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_PLATFORM_TIMER_PM_H
#define DRV_TIMER_PLATFORM_TIMER_PM_H

#include <stdint.h>

int32_t timer_resume(uint32_t flag);
int32_t timer_suspend(uint32_t flag);

#define TIMER_SUSPEND_S3 0
#define TIMER_SUSPEND_S4 1
#define TIMER_RESUME_S3  0
#define TIMER_RESUME_S4  1

#endif /* DRV_TIMER_PLATFORM_TIMER_PM_H */
