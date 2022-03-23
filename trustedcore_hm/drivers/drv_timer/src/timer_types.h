/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for timer types
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_SRC_TIMER_TYPES_H
#define DRV_TIMER_SRC_TIMER_TYPES_H

#define TIMER_COUNT_MAX_32BIT 0xFFFFFFFF
#define TIMER_COUNT_MAX_64BIT ((uint64_t)0xFFFFFFFFFFFFFFFF)
#define FREE_TIMER_COUNT_MAX 18446744073700
#define TIMER_COUNT_MIN 0x1
#define TIMER_VALUE_INVALID 0

#define NULL_ENENT_HANDLER 0
#define TMR_DRV_SUCCESS 0
#define TMR_DRV_ERROR 1

#endif /* DRV_TIMER_SRC_TIMER_TYPES_H */

