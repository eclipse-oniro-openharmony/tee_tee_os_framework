/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: access generic timer
 * Create: 2021-7-29
 */
#ifndef LIBTIMER_GENERIC_TIMER_H
#define LIBTIMER_GENERIC_TIMER_H
#include <stdint.h>

static inline uint64_t get_cntpct_el0(void)
{
    uint64_t val;
    __asm__ volatile("mrs %0, CNTPCT_EL0" : "=r"(val));
    return val;
}

static inline uint64_t get_cntfrq_el0(void)
{
    uint64_t val;
    __asm__ volatile("mrs %0, CNTFRQ_EL0" : "=r"(val));
    return val;
}
#endif
