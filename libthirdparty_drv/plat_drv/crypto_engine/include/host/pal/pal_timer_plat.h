/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: platform adapter for timer
 * Author     : SecurityEngine
 * Create     : 2018/08/10
 */
#ifndef __PAL_TIMER_PLAT_H__
#define __PAL_TIMER_PLAT_H__

/* timer is backward counter */
#define PAL_TIMER_REVERSAL(end, begin) ((begin) > (end))
#define PAL_TIMER_INTERVAL(end, begin) (u32)((end) - (begin))

#endif /* __PAL_TIMER_PLAT_H__ */

