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
#include <timer_sys.h>
#include <timer_types.h>

#define REG_BASEADDR_INVALID 0x0
#define TIMER_VALUE_INVALID 0
#define TICK_TIMER_OFFSET 0x0
#define FREE_RUNNING_TIMER_OFFSET 0x20
#define IRQ_ACK_VALUE 0x3
#define TIMER_MODE_VALUE 0x2U

uint32_t timer_reg_offset_get(uint32_t tim_mod_index)
{
    if (tim_mod_index == FREE_RUNNING_TIMER_NUM)
        return FREE_RUNNING_TIMER_OFFSET;
    else
        return TICK_TIMER_OFFSET;
}

void timer_clk_enable(void)
{
}

void timer_freq_init(void)
{
    uint32_t ctrl;
    write32((uintptr_t)SGPT_IRQACK, IRQ_ACK_VALUE);
    ctrl = (SGPT_CLK_SETTING);
    write32((uintptr_t)SGPT_CLK, ctrl);  /* free run timer */
    write32((uintptr_t)SGPT_CLK1, ctrl); /* tick timer */
}

void timer_clk_init(void)
{
    timer_freq_init();
    timer_clk_enable();
}

static void secure_mtk_timer_enable(uint32_t timer_type)
{
    uint32_t val;

    if (timer_type == FREE_RUNNING_TIMER_NUM) {
        val = read32(SGPT_CON1);
        val |= SGPT_EN;
        write32((uintptr_t)SGPT_CON1, val);
    } else if (timer_type == TICK_TIMER_NUM) {
        val = read32(SGPT_CON);
        val |= SGPT_EN;
        write32((uintptr_t)SGPT_CON, val);
    } else {
        hm_error("error: invalid timer = %u\n", timer_type);
    }
}

static void secure_mtk_timer_config(uint32_t timer, uint32_t mode, uint64_t usecs)
{
    uint32_t val;
    uint32_t try = 0;

    val = read32(SGPT_IRQEN);
    if (timer == FREE_RUNNING_TIMER_NUM) {
        usecs = FREE_TIMER_COUNT_MAX;
        write32((uintptr_t)SGPT_CON1, mode | TIMER_MODE_VALUE); /* set mode and disable */
        val &= (~SGPT_INT_EN1);
        write32((uintptr_t)SGPT_IRQEN, val);
        write32((uintptr_t)SGPT_COMPARE1L, LOWER_32_BITS(usecs)); /* low 32 bit */
        write32((uintptr_t)SGPT_COMPARE1H, UPPER_32_BITS(usecs)); /* high 32 bit */
        while (try < TIMER_MAX_TRY_TIMES) {
            /* wait for the clear operation done */
            if ((read32(SGPT_DAT1L)) || (read32(SGPT_DAT1H)))
                try++;
            else
                break;
        }

        if (try >= TIMER_MAX_TRY_TIMES)
            hm_error("error: clear freerun timer fail\n");
    } else if (timer == TICK_TIMER_NUM) {
        write32((uintptr_t)SGPT_CON, mode | TIMER_MODE_VALUE); /* set mode and disable */
        val |= SGPT_INT_EN;
        write32((uintptr_t)SGPT_IRQEN, val);
        write32((uintptr_t)SGPT_COMPARE, LOWER_32_BITS(usecs));
        while (try < TIMER_MAX_TRY_TIMES) {
            if (read32(SGPT_DAT)) /* wait for the clear operation done */
                try++;
            else
                break;
        }

        if (try >= TIMER_MAX_TRY_TIMES)
            hm_error("error: clear tick timer fail\n");
    } else {
        hm_error("error: timer type is not support\n");
    }
}

uint64_t timer_get_value(uint32_t timer_base, uint32_t tim_mod_index)
{
    uint32_t reg_offset;

    if (timer_base == REG_BASEADDR_INVALID) {
        hm_error("invalid timer base address!\n");
        return TIMER_VALUE_INVALID;
    }
    reg_offset = timer_reg_offset_get(tim_mod_index);

    uint32_t try;
    uint32_t tmp;

    if ((timer_base == FREE_RUNNING_TIMER_BASE_TIMEL) || (timer_base == TICK_TIMER_BASE)) {
        try = 0;
        while (try < TIMER_MAX_TRY_TIMES) {
            tmp = read32(timer_base + TIMER_VALUE + reg_offset);
            if (tmp)
                break;
            else
                try++;
        }
        if (tmp == REG_BASEADDR_INVALID) {
            hm_error("error: read timer fail\n");
            return TIMER_VALUE_INVALID;
        }
        return tmp;
    } else {
        return read32(timer_base + TIMER_VALUE + reg_offset);
    }
}


void timer_set_value(uint32_t timer_base, uint32_t tim_mod_index, uint32_t mode, uint64_t usecs)
{
    (void)timer_base;

    if (tim_mod_index == TICK_TIMER_NUM) {
        if (usecs > UINT32_MAX)
            usecs = UINT32_MAX;
    }

    if (mode == MODE_FREE_RUNNING)
        secure_mtk_timer_config(tim_mod_index, SGPT_FREERUN, usecs);
    else if (mode == MODE_ONESHOT)
        secure_mtk_timer_config(tim_mod_index, SGPT_ONESHOT, usecs);
    else
    hm_error("error: timer type is not support, timer set value failed!\n");
}

uint64_t timer_free_running_value_get(void)
{
    uint64_t time;
    uint64_t time_low;
    uint64_t time_high;

    time_low = timer_get_value(FREE_RUNNING_TIMER_BASE_TIMEL, FREE_RUNNING_TIMER_NUM);
    time_high = timer_get_value(FREE_RUNNING_TIMER_BASE_TIMEH, FREE_RUNNING_TIMER_NUM);

    time = get_time_value(time_high, time_low);

    return time;
}

void timer_enable(uint32_t timer_base, uint32_t tim_mod_index)
{
    (void)timer_base;
    secure_mtk_timer_enable(tim_mod_index);
}

void timer_disable(uint32_t timer_base, uint32_t tim_mod_index)
{
    uint32_t tmp;

    (void)timer_base;
    if (tim_mod_index == TICK_TIMER_NUM) {
        tmp = read32(SGPT_CON);
        tmp &= ~SGPT_EN;
        write32((uintptr_t)SGPT_CON, tmp);
    } else if (tim_mod_index == FREE_RUNNING_TIMER_NUM) {
        tmp = read32(SGPT_CON1);
        tmp &= ~SGPT_EN;
        write32((uintptr_t)SGPT_CON1, tmp);
    } else {
        hm_error("error: timer type is not support!\n");
    }
}

void timer_free_running_enable(void)
{
    timer_set_value(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM, MODE_FREE_RUNNING, TIMER_COUNT_MAX);
    timer_enable(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
}

uint32_t secure_timer_mis_read(uint32_t timer_base, uint32_t tim_mod_index)
{
    uint32_t status;

    (void)timer_base;
    status = read32(SGPT_IRQSTATUS);
    if (tim_mod_index == FREE_RUNNING_TIMER_NUM)
        return (status & SGPT_STATUS1);
    else
        return (status & SGPT_STATUS);
}

/*
 * Must set timer10 to non secure to keep timer counter continue to decrease when deep sleep
 * else timer counter stopped when system goto deep sleep.
 * When system resume, set timer to secure
 */
void set_timer_secure(void)
{
    hm_debug("mtk platform do nothing\n");
}

void set_timer_non_secure(void)
{
    hm_debug("mtk platform do nothing\n");
}

void secure_timer_irq_clear(uint32_t timer_base, uint32_t tim_mod_index)
{
    uint32_t tmp;

    (void)timer_base;
    tmp = read32(SGPT_IRQACK);
    if (tim_mod_index == TICK_TIMER_NUM) {
        tmp |= SGPT_ACK;
    } else {
        hm_error("invalid mod index!\n");
        return;
    }

    write32((uintptr_t)SGPT_IRQACK, tmp);
}
