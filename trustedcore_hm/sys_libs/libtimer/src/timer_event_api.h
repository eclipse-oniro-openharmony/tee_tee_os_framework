/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file of timer event api
 * Create: 2019-08-20
 */

#ifndef SYS_LIBS_LIBTIMER_A32_SRC_TIMER_EVENT_API_H
#define SYS_LIBS_LIBTIMER_A32_SRC_TIMER_EVENT_API_H

#include <posix_types.h>
#include <sys_timer.h>
#include <timer.h>

timer_event *SRE_TimerEventCreate(sw_timer_event_handler handler, int32_t timer_class, void *priv_data);
uint32_t SRE_TimerEventDestroy(timer_event *t_event);

#endif /* SYS_LIBS_LIBTIMER_A32_SRC_TIMER_EVENT_API_H */
