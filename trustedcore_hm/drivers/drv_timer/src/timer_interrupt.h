/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for timer_interrupt
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_PLATFORM_TIMER_INTERRUPT_H
#define DRV_TIMER_PLATFORM_TIMER_INTERRUPT_H

#include <stdint.h>

uint32_t timer_interrupt_init(void);
void timer_free_running_fiq_handler(void);
void timer_oneshot_fiq_handler(void);

#endif /* DRV_TIMER_PLATFORM_TIMER_INTERRUPT_H */
