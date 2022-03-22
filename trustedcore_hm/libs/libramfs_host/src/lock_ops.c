/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: ramfs implementation
 * Create: 2018-05-18
 */
#include "lock_ops.h"
#include <stdint.h>
#include <hmlog.h>

#define COUNT_MAX 0x7fffffff

bool trylockr(volatile int32_t *l)
{
    int32_t val, cnt;
    if (l == NULL)
        hm_panic("lock ptr is NULL\n");
    if (*l < 0)
        hm_panic("invalid lock value %d\n", *l);
    do {
        val = *l;
        cnt = (uint32_t)val & COUNT_MAX;
        if (cnt == COUNT_MAX || cnt + 1 == COUNT_MAX)
            return false;
    } while (!__sync_bool_compare_and_swap(l, val, val + 1));
    return true;
}

bool trylockw(volatile int32_t *l)
{
    if (l == NULL)
        hm_panic("lock ptr is NULL\n");
    if (*l < 0)
        hm_panic("invalid lock value %d\n", *l);
    return __sync_bool_compare_and_swap(l, 0, COUNT_MAX);
}

void unlock(volatile int32_t *l)
{
    int32_t val, cnt, newval;
    if (l == NULL)
        hm_panic("lock ptr is NULL\n");
    if (*l <= 0)
        hm_panic("invalid lock value %d\n", *l);
    do {
        val    = *l;
        cnt    = (uint32_t)val & COUNT_MAX;
        newval = (cnt == COUNT_MAX || cnt == 1) ? 0 : (val - 1);
    } while (!__sync_bool_compare_and_swap(l, val, newval));
}
