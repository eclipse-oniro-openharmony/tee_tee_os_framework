/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: pal time function
 * Author: m00475438
 * Create: 2018-12-20
 */

#include <pal_timer.h>
#include <time.h>
#include <sys/time.h>
#include <sre_hwi.h>
#include <hieps_timer.h>

#define BSP_THIS_MODULE BSP_MODULE_SYS

u32 pal_us2tick(u32 us)
{
	return (u32)US2TICK(us);
}

u32 pal_tick2us(u32 tick)
{
	return (u32)TICK2US(tick);
}

u32 pal_timer_value(void)
{
	return (u32)hieps_get_timer_value();
}

void pal_udelay(u32 us)
{
	hieps_udelay(us);
}
