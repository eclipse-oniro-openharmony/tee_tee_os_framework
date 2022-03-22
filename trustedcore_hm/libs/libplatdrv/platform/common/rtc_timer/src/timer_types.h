/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Header file for timer types
 * Create: 2021-05-27
 */

#ifndef RTC_TIMER_DRIVER_TIMER_TYPES_H
#define RTC_TIMER_DRIVER_TIMER_TYPES_H

#define TIMER_COUNT_MAX_32BIT 0xFFFFFFFF
#define TIMER_COUNT_MAX_64BIT ((uint64_t)0xFFFFFFFFFFFFFFFF)
#define FREE_TIMER_COUNT_MAX 18446744073700
#define TIMER_COUNT_MIN 0x1
#define TIMER_VALUE_INVALID 0

#define NULL_ENENT_HANDLER 0
#define TMR_DRV_SUCCESS 0
#define TMR_DRV_ERROR 1

#endif /* RTC_TIMER_DRIVER_TIMER_TYPES_H */
