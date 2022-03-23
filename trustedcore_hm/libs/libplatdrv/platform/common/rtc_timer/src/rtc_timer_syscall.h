/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Header file for timer common.
 * Create: 2021-05-27
 */

#ifndef RTC_TIMER_DRIVER_RTC_TIMER_SYSCALL_H
#define RTC_TIMER_DRIVER_RTC_TIMER_SYSCALL_H

#include <stdint.h>

int32_t rtc_timer_syscall(int32_t swi_id, struct drv_param *params, uint64_t permissions);

#endif /* RTC_TIMER_DRIVER_RTC_TIMER_SYSCALL_H */
