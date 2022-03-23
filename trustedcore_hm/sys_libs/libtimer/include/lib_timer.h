/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, timer function
 * Create: 2019-12-10
 */
#ifndef LIBTIMER_A32_LIB_TIMER_H
#define LIBTIMER_A32_LIB_TIMER_H
#include "sys_timer.h"

UINT32 SRE_TimerEventDestroy(timer_event *pstTevent);
UINT32 SRE_TimerEventStop(timer_event *pstTevent);
#endif /* LIBTIMER_A32_LIB_TIMER_H */
