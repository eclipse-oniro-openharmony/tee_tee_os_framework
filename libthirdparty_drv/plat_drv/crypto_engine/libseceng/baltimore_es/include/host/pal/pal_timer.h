/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: timer api for pal
 * Author     : l00370476, liuchong13@huawei.com
 * Create     : 2018/08/10
 */
#ifndef __PAL_TIMER_H__
#define __PAL_TIMER_H__
#include <pal_types.h>
#include <pal_timer_plat.h>

/* default timer is forward counter */
#ifndef PAL_TIMER_REVERSAL
/* check if timer is reversal */
#define PAL_TIMER_REVERSAL(end, begin) ((end) < (begin))
#endif /* PAL_TIMER_REVERSAL */

#ifndef PAL_TIMER_INTERVAL
/* timer interval */
#define PAL_TIMER_INTERVAL(end, begin) (u32)((end) - (begin))
#endif /* PAL_TIMER_INTERVAL */

u64 pal_timer_value(void);
u64 pal_us2tick(u32 us);
u32 pal_tick2us(u32 tick);

void pal_udelay(u32 us);
void pal_delay_cycles(u32 nops);

#endif /* __PAL_TIMER_H__ */

