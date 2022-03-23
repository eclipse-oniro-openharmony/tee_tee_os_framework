/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: inner common timer function interface
 * Author     : z00293770, zhangyangyang1@huawei.com
 * Create     : 2018/08/14
 */
#ifndef __SECENG_TIMER_H__
#define __SECENG_TIMER_H__
#include <pal_types.h>
#include <pal_timer.h>

u32 random_udelay(u32 min, u32 max);
u32 random_delay_cycles(u32 min, u32 max);

#endif/* __SECENG_TIMER_H__ */

