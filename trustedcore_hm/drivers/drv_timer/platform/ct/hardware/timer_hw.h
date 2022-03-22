/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Header file for timer_hw
 * Author: hemuyang1@huawei.com
 * Create: 2021-03-09
 */

#ifndef DRV_TIMER_PLATFORM_TIMER_HW_H
#define DRV_TIMER_PLATFORM_TIMER_HW_H

#include <stdint.h>

#define TIMER_COUNT_MIN 0x1
#define TIMER_VALUE_INVALID 0

enum timer_mode {
    MODE_FREE_RUNNING,
    MODE_PERIODIC,
    MODE_ONESHOT
};

void timer_freq_init(void);
void timer_clk_enable(void);
void timer_clk_init(void);
void timer_enable(uint32_t timer_base, uint32_t timer_module_index);
void timer_disable(uint32_t timer_base, uint32_t tim_mod_index);
uint64_t timer_get_value(uint32_t timer_base, uint32_t tim_mod_index);
void timer_free_running_enable(void);
uint64_t timer_free_running_value_get(void);
void timer_set_value(uint32_t timer_base, uint32_t tim_mod_index, uint32_t mode, uint64_t usecs);
uint32_t secure_timer_mis_read(uint32_t timer_base, uint32_t tim_mod_index);
void set_timer_secure(void);
void set_timer_non_secure(void);
void secure_timer_irq_clear(uint32_t timer_base, uint32_t tim_mod_index);

#endif /* DRV_TIMER_PLATFORM_TIMER_HW_H */
