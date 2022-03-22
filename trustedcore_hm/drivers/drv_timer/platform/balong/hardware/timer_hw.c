/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Safe time function setting
 * Author: hepengfei hepengfei7@huawei.com
 * Create: 2019-08-20
 */
#include "timer_hw.h"
#include <hmlog.h>
#include <drv_module.h>
#include <register_ops.h>
#include <sys_timer.h>
#include <timer_reg.h>
#include <timer_types.h>

#define REG_BASEADDR_INVALID 0x0
#define TIMER_VALUE_INVALID 0
#define TICK_TIMER_OFFSET 0x0
#define FREE_RUNNING_TIMER_OFFSET 0x20
#define TIMER_MODE_VALUE 0x2U
#define INT_CLEAR_VALUE  0x1
#define REG_BASEADDR_INVALID 0x0

uint32_t timer_reg_offset_get(uint32_t tim_mod_index)
{
    if (tim_mod_index == FREE_RUNNING_TIMER_NUM)
        return FREE_RUNNING_TIMER_OFFSET * tim_mod_index;
    else
        return TICK_TIMER_OFFSET;
}

void timer_clk_enable(void)
{
}

void timer_freq_init(void)
{
}

void timer_clk_init(void)
{
}

uint64_t timer_get_value(uint32_t timer_base, uint32_t tim_mod_index)
{
    uint32_t reg_offset;

    if (timer_base == REG_BASEADDR_INVALID) {
        hm_error("invalid timer base address!\n");
        return TIMER_VALUE_INVALID;
    }

    reg_offset = timer_reg_offset_get(tim_mod_index);
    return read32((uintptr_t)(timer_base + TIMER_VALUE + reg_offset));
}

void timer_set_value(uint32_t timer_base, uint32_t tim_mod_index, uint32_t mode, uint64_t usecs)
{
    uint32_t val;
    uint32_t reg_offset;
    uint32_t u_secs;

    if (timer_base == REG_BASEADDR_INVALID) {
        hm_error("invalid timer base address!\n");
        return;
    }

    reg_offset = timer_reg_offset_get(tim_mod_index);

    /* generating irq setup timer */
    val = read32((uintptr_t)(timer_base + TIMER_CTRL + reg_offset));
    val &= ~TIMER_CTRL_ENABLE;
    val |= (TIMER_CTRL_32BIT | TIMER_CTRL_IE);

    if (mode == MODE_FREE_RUNNING) {
        val &= ~TIMER_CTRL_ONESHOT;
        val &= ~TIMER_CTRL_PERIODIC;
    } else if (mode == MODE_ONESHOT) {
        val |= TIMER_CTRL_ONESHOT;
    } else {
        val &= ~TIMER_CTRL_ONESHOT;
        val |= TIMER_CTRL_PERIODIC;
    }

    /* this is only low 32bit */
    u_secs = usecs & 0xFFFFFFFF;
    write32((uintptr_t)(timer_base + TIMER_CTRL + reg_offset), val);
    write32((uintptr_t)(timer_base + TIMER_LOAD + reg_offset), u_secs);
}

uint64_t timer_free_running_value_get(void)
{
    uint64_t result;
    uint64_t time;

    /* get free running timer */
    time = timer_get_value(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
    if (time == TIMER_VALUE_INVALID)
        return TIMER_VALUE_INVALID;

    result = (time <= TIMER_COUNT_MAX) ? (TIMER_COUNT_MAX - time) : 0;
    return result;
}

void timer_enable(uint32_t timer_base, uint32_t tim_mod_index)
{
    uint32_t reg_offset;
    uint32_t ctrl;

    /* timer base is ok ? */
    if (timer_base == REG_BASEADDR_INVALID) {
        hm_error("invalid timer base address!\n");
        return;
    }
    reg_offset = timer_reg_offset_get(tim_mod_index);
    ctrl = read32((uintptr_t)(timer_base + TIMER_CTRL + reg_offset));
    ctrl |= TIMER_CTRL_ENABLE;
    write32((uintptr_t)(timer_base + TIMER_CTRL + reg_offset), ctrl);

    hm_debug("timer base ctrl = 0x%x\n", (timer_base + TIMER_CTRL + reg_offset));
    hm_debug("timer base ctrl value = 0x%x\n", ctrl);
}

void timer_disable(uint32_t timer_base, uint32_t tim_mod_index)
{
    uint32_t ctrl;
    uint32_t reg_offset;
    if (timer_base == REG_BASEADDR_INVALID) {
        hm_error("invalid timer base address!\n");
        return;
    }

    reg_offset = timer_reg_offset_get(tim_mod_index);
    ctrl = read32((uintptr_t)(timer_base + TIMER_CTRL + reg_offset));
    ctrl &= ~TIMER_CTRL_ENABLE;
    write32((uintptr_t)(timer_base + TIMER_CTRL + reg_offset), ctrl);
}

void timer_free_running_enable(void)
{
    timer_set_value(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM, MODE_FREE_RUNNING, TIMER_COUNT_MAX);
    timer_enable(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
}

uint32_t secure_timer_mis_read(uint32_t timer_base, uint32_t tim_mod_index)
{
    uint32_t tmp_reg;
    uint32_t reg_offset;

    if (timer_base == REG_BASEADDR_INVALID) {
        hm_error("invalid timer base address!\n");
        return TIMER_VALUE_INVALID;
    }
    reg_offset = timer_reg_offset_get(tim_mod_index);
    tmp_reg = read32((uintptr_t)(timer_base + TIMER_MIS + reg_offset));
    return tmp_reg;
}

/*
 * Must set timer10 to non secure to keep timer counter continue to decrease when deep sleep
 * else timer counter stopped when system goto deep sleep.
 * When system resume, set timer to secure
 */
void set_timer_secure(void)
{
}

void set_timer_non_secure(void)
{
}

void secure_timer_irq_clear(uint32_t timer_base, uint32_t tim_mod_index)
{
    uint32_t reg_offset;
    if (timer_base == REG_BASEADDR_INVALID) {
        hm_error("invalid timer base address!\n");
        return;
    }

    reg_offset = timer_reg_offset_get(tim_mod_index);
    write32((uintptr_t)(timer_base + TIMER_INTCLR + reg_offset), INT_CLEAR_VALUE);
}
