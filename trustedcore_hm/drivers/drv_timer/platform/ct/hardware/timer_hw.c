/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Safe time function setting
 * Author: hemuyang1@huawei.com
 * Create: 2021-03-09
 */
#include "timer_hw.h"
#include <hmlog.h>
#include <drv_module.h>
#include <register_ops.h>
#include <sys_timer.h>
#include <timer_reg.h>
#include <timer_sys.h>
#include <timer_types.h>

#define REG_BASEADDR_INVALID 0x0
#define TIMER_VALUE_INVALID 0
#define TICK_TIMER_OFFSET 0x0
#define FREE_RUNNING_TIMER_OFFSET 0x20
#define TIMER_MODE_VALUE 0x2U

#define TIMER_COUNT_MODE     (1U << 0)
#define TIMER_BIT_MODE       (1U << 1)
#define TIMER_INTERRUPT_TYPE (1U << 4)
#define TIMER_MASK_INTERRUPT (1U << 5)
#define TIMER_COUNT_TYPE     (1U << 6)
#define TIMER_ENABLE         (1U << 7)
#define TIMER_32K_FRQ        0xFFFFFCFC
#define MAX_32               0xFFFFFFFF
#define SHIFT_32             32

void timer_clk_enable(void)
{
    uint32_t ctrl;
    ctrl = read32((void *)(SC_SECURE_TIMER_CLK_ST));
    if ((ctrl & SECURE_TIMER_CLK_EN_VALUE) == (SECURE_TIMER_CLK_EN_VALUE))
        return;
    write32(SC_SECURE_TIMER_CLK_EN, SECURE_TIMER_CLK_EN_VALUE);
}

static void timer_interrupt_choose(void)
{
    uint32_t val;
    uint32_t val2;
    uint32_t ctrl;
    uint32_t ctrl2;

    val = read32((void *)TIMER64_CONTROL_REG0);
    val &= ~TIMER_MASK_INTERRUPT;
    write32(TIMER64_CONTROL_REG0, val);
    val2 = read32((void *)TIMER64_CONTROL_REG1);
    val2 &= ~TIMER_MASK_INTERRUPT;
    write32(TIMER64_CONTROL_REG1, val2);

    ctrl = read32((void *)TIMER64_CONTROL_REG0);
    ctrl2 = read32((void *)TIMER64_CONTROL_REG1);
    ctrl &= ~TIMER_INTERRUPT_TYPE; /* type0 interrupt */
    ctrl2 &= ~TIMER_INTERRUPT_TYPE;
    write32(TIMER64_CONTROL_REG0, ctrl);
    write32(TIMER64_CONTROL_REG1, ctrl2);

    val = read32((void *)TIMER64_CONTROL_REG0);
    val |= TIMER_MASK_INTERRUPT;
    write32(TIMER64_CONTROL_REG0, val);
    val2 = read32((void *)TIMER64_CONTROL_REG1);
    val2 |= TIMER_MASK_INTERRUPT;
    write32(TIMER64_CONTROL_REG1, val2);
}

void timer_freq_init(void)
{
    uint32_t freq_value;
    timer_interrupt_choose();
    freq_value = read32((void *)SC_SECURE_TIMER_CLK_SEL);
    freq_value &= SECURE_TIMER_CLK_50M;
    write32(SC_SECURE_TIMER_CLK_SEL, freq_value); /* set timer 50M */
}

uint64_t timer_get_value(uint32_t timer_base, uint32_t tim_mod_index)
{
    (void)timer_base;

    void *ptr_reg_l = NULL;
    void *ptr_reg_h = NULL;

    if (tim_mod_index == FREE_RUNNING_TIMER_NUM) {
        ptr_reg_l = (void *)TIMER64_VALUE_L_REG0;
        ptr_reg_h = (void *)TIMER64_VALUE_H_REG0;
    } else {
        ptr_reg_l = (void *)TIMER64_VALUE_L_REG1;
        ptr_reg_h = (void *)TIMER64_VALUE_H_REG1;
    }

    uint32_t time_low = read32(ptr_reg_l);
    uint32_t time_high = read32(ptr_reg_h);
    uint64_t val = get_time_value(time_high, time_low);
    return val;
}

void timer_set_value(uint32_t timer_base, uint32_t tim_mod_index, uint32_t mode, uint64_t usecs)
{
    (void)timer_base;

    void *ptr_ctrl = NULL;
    void *ptr_load = NULL;
    void *ptr_load_h = NULL;
    if (tim_mod_index == FREE_RUNNING_TIMER_NUM) {
        ptr_ctrl = (void *)TIMER64_CONTROL_REG0;
        ptr_load = (void *)TIMER64_LOAD_L_REG0;
        ptr_load_h = (void *)TIMER64_LOAD_H_REG0;
    } else {
        ptr_ctrl = (void *)TIMER64_CONTROL_REG1;
        ptr_load = (void *)TIMER64_LOAD_L_REG1;
        ptr_load_h = (void *)TIMER64_LOAD_H_REG1;
    }

    uint32_t ctrl = read32((void *)ptr_ctrl);
    ctrl |= TIMER_BIT_MODE; /* 64 bit mode */
    ctrl &= ~TIMER_ENABLE; /* disable timer */
    ctrl |= TIMER_MASK_INTERRUPT;  /* not mask interrupt */

    if (mode == MODE_FREE_RUNNING) {
        ctrl &= ~TIMER_COUNT_MODE; /* close one shot */
        ctrl &= ~TIMER_COUNT_TYPE; /* free running mode */
    } else if (mode == MODE_ONESHOT) {
        ctrl |= TIMER_COUNT_MODE; /* open one shot */
    } else {
        hm_debug("invalid timer mode!\n");
        return;
    }

    write32((uintptr_t)ptr_ctrl, ctrl);
    write32((uintptr_t)ptr_load, usecs);
    write32((uintptr_t)ptr_load_h, (usecs >> SHIFT_32) & MAX_32);
}

uint64_t timer_free_running_value_get(void)
{
    uint64_t time = timer_get_value(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
    uint64_t result = TIMER_COUNT_MAX - time;
    return result;
}

void timer_enable(uint32_t timer_base, uint32_t tim_mod_index)
{
    (void)timer_base;

    uint32_t ctrl;
    void *ptr_ctrl = NULL;
    if (tim_mod_index == FREE_RUNNING_TIMER_NUM)
        ptr_ctrl = (void *)TIMER64_CONTROL_REG0;
    else
        ptr_ctrl = (void *)TIMER64_CONTROL_REG1;

    ctrl = read32(ptr_ctrl);
    ctrl |= TIMER_ENABLE; /* enable timer */
    write32((uintptr_t)ptr_ctrl, ctrl);
}

void timer_disable(uint32_t timer_base, uint32_t tim_mod_index)
{
    (void)timer_base;

    uint32_t ctrl;
    void *ptr_ctrl = NULL;
    if (tim_mod_index == FREE_RUNNING_TIMER_NUM)
        ptr_ctrl = (void *)TIMER64_CONTROL_REG0;
    else
        ptr_ctrl = (void *)TIMER64_CONTROL_REG1;

    ctrl = read32(ptr_ctrl);
    ctrl &= ~TIMER_ENABLE; /* disable timer */
    write32((uintptr_t)ptr_ctrl, ctrl);
}

void timer_clk_init(void)
{
    timer_freq_init();
    timer_clk_enable();
}

void timer_free_running_enable(void)
{
    timer_set_value(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM, MODE_FREE_RUNNING, TIMER_COUNT_MAX);
    timer_enable(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
}

uint32_t secure_timer_mis_read(uint32_t timer_base, uint32_t tim_mod_index)
{
    (void)timer_base;

    uint32_t ctrl;
    void *ptr_ctrl = NULL;
    if (tim_mod_index == FREE_RUNNING_TIMER_NUM)
        ptr_ctrl = (void *)TIMER64_MIS_REG0;
    else
        ptr_ctrl = (void *)TIMER64_MIS_REG1;

    ctrl = read32(ptr_ctrl);
    return ctrl;
}

void set_timer_secure(void)
{
    hm_debug("ct platform do nothing\n");
}

void set_timer_non_secure(void)
{
    hm_debug("ct platform do nothing\n");
}

void secure_timer_irq_clear(uint32_t timer_base, uint32_t tim_mod_index)
{
    (void)timer_base;
    void *ptr_ctrl = NULL;
    if (tim_mod_index == FREE_RUNNING_TIMER_NUM)
        ptr_ctrl = (void *)TIMER64_INTCLR_REG0;
    else
        ptr_ctrl = (void *)TIMER64_INTCLR_REG1;

    write32((uintptr_t)ptr_ctrl, 1);
}
