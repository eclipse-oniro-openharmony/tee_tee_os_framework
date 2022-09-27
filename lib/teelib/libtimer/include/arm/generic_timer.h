/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: access generic timer
 * Create: 2022-04-22
 */
#ifndef LIBTIMER_GENERIC_TIMER_H
#define LIBTIMER_GENERIC_TIMER_H
#include <stdint.h>

static inline uint64_t get_cntpct_el0(void)
{
    uint64_t val;
    __asm__ volatile("mrrc p15, 0, %Q[val], %R[val], c14" : [val] "=r" (val));
    return val;
}

static inline uint32_t get_cntfrq_el0(void)
{
    uint32_t val;
    __asm__ volatile("mrc p15, 0,  %0, c14,  c0, 0" : "=r"(val));
    return val;
}
#endif
