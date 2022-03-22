/**
 * @file   : pal_timer.h
 * @brief  : define types
 *           platform-dependent types is defined in pal_timer_plat.h
 *           platform-independent types is defined in pal_timer.h
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2018/08/10
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __PAL_TIMER_H__
#define __PAL_TIMER_H__
#include <pal_types.h>
#include <pal_timer_plat.h>

/**< default timer is forward counter */
#ifndef PAL_TIMER_REVERSAL
/**< check if timer is reversal */
#define PAL_TIMER_REVERSAL(end, begin) (end < begin)
#endif /* PAL_TIMER_REVERSAL */

#ifndef PAL_TIMER_INTERVAL
/**< timer interval */
#define PAL_TIMER_INTERVAL(end, begin) (u32)((end) - (begin))
#endif /* PAL_TIMER_INTERVAL */

u32 pal_us2tick(u32 us);
u32 pal_tick2us(u32 tick);
u32 pal_timer_value(void);

void pal_udelay(u32 us);
void pal_delay_cycles(u32 nops);

u32 pal_random(void);
u32 pal_random_udelay(u32 min, u32 max);
u32 pal_random_delay_cycles(u32 min, u32 max);

#endif /* __PAL_TIMER_H__ */

