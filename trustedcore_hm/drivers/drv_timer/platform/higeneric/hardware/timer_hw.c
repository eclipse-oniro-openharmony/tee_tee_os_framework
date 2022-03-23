/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Safe time function setting
 * Create: 2019-08-20
 */
#include "timer_hw.h"
#include <hmlog.h>
#include <drv_module.h>
#include <register_ops.h>
#include <sys_generic.h>
#include <sys_timer.h>
#include <timer_reg.h>
#include <timer_types.h>
#include <timer_rtc.h>
#include <timer_pm.h>

#define REG_BASEADDR_INVALID 0x0
#define TIMER_VALUE_INVALID 0
#define INT_CLEAR_VALUE  0x1
#define TIMER_S4_DEFAULT_PERIOD 60

#define TICK_TIMER_OFFSET 0x0
#ifdef HI_TIMER_V500
#define FREE_RUNNING_TIMER_OFFSET 0x400
#else
#define FREE_RUNNING_TIMER_OFFSET 0x20
#endif

static uint64_t g_syscounter_suspend = 0;
static uint64_t g_free_time_val = 0;
static uint64_t g_suspend_time = 0;

uint32_t timer_reg_offset_get(uint32_t tim_mod_index)
{
    if (tim_mod_index == FREE_RUNNING_TIMER_NUM)
        return FREE_RUNNING_TIMER_OFFSET;
    else
        return TICK_TIMER_OFFSET;
}

void timer_clk_enable(void)
{
    uint32_t ctrl;

    /* enable timer1 */
    ctrl = read32(SCPERCLKEN0_SEC);
    ctrl |= TIMER_GT_CLK_TIMER1;
    ctrl |= TIMER_GT_PCLK_TIMER1;
    write32(SCPEREN0_SEC, ctrl);

    /* enable timer7 */
    ctrl = read32(SCPERCLKEN1);
    ctrl |= TIMER_GT_CLK_TIMER7;
    ctrl |= TIMER_GT_PCLK_TIMER7;
    write32(SCPEREN1, ctrl);
}

#ifdef TIMER_S3_ADJUST_FREQ
void timer_free_run_reduce_freq(void)
{
    uint32_t ctrl;
    /* set timer10 32.768/16kHZ */
    ctrl = read32(FREE_RUNNING_TIMER_BASE + TIMER_CTRL + FREE_RUNNING_TIMER_OFFSET);
    ctrl |= TIMER_CTRL_DIV16;
    write32(FREE_RUNNING_TIMER_BASE + TIMER_CTRL + FREE_RUNNING_TIMER_OFFSET, ctrl);
}

void timer_free_run_restore_freq(void)
{
    uint32_t ctrl;
    /* set timer10 32.768kHZ */
    ctrl = read32(FREE_RUNNING_TIMER_BASE + TIMER_CTRL + FREE_RUNNING_TIMER_OFFSET);
    ctrl &= ~(TIMER_CTRL_ONESHOT | TIMER_CTRL_DIV16 | TIMER_CRTL_RESERVED);
    write32(FREE_RUNNING_TIMER_BASE + TIMER_CTRL + FREE_RUNNING_TIMER_OFFSET, ctrl);
}
#endif

void timer_freq_init(void)
{
    uint32_t ctrl;

#ifdef HI_TIMER_V500
    /* set timer10 32.768kHz */
    ctrl = read32(FREE_RUNNING_TIMER_BASE + TIMER_CLK_CTRL + FREE_RUNNING_TIMER_OFFSET);
    ctrl &= ~CNT_TIMER_EN_SEL;
    write32(FREE_RUNNING_TIMER_BASE + TIMER_CLK_CTRL + FREE_RUNNING_TIMER_OFFSET, ctrl);

    /* set timer70 clk 32.768kHz */
    ctrl = read32(TICK_TIMER_BASE + TIMER_CLK_CTRL + TICK_TIMER_OFFSET);
    ctrl &= ~CNT_TIMER_EN_SEL;
    write32(TICK_TIMER_BASE + TIMER_CLK_CTRL + TICK_TIMER_OFFSET, ctrl);
#else
    /* set timer10 32.768kHz */
    ctrl = read32(SCTIMERCTRL_SEC);
    ctrl &= ~TIMER1_B_EN_SEL;
    write32(SCTIMERCTRL_SEC, ctrl);

    /* set timer70 clk 32.768kHz */
    ctrl = read32(SCTIMERCTRL1);
    ctrl &= ~TIMER7_A_EN_SEL;
    write32(SCTIMERCTRL1, ctrl);

    ctrl = read32(SCTIMERCTRL_SEC);
    ctrl |= SECURE_TIMER_FORCE_HIGH;
    write32(SCTIMERCTRL_SEC, ctrl);
#endif
}

void timer_clk_init(void)
{
    timer_freq_init();
    timer_clk_enable();
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

    /* setup timer for generating irq */
    val = read32((uintptr_t)(timer_base + TIMER_CTRL + reg_offset));
    val &= ~TIMER_CTRL_ENABLE;
    val |= TIMER_CTRL_32BIT;
#ifdef HI_TIMER_V500
    val &= ~TIMER_CTRL_IE;
#else
    val |= TIMER_CTRL_IE;
#endif

    /* choose timer mode */
    if (mode == MODE_FREE_RUNNING) {
        val &= ~TIMER_CTRL_ONESHOT;
        val &= ~TIMER_CTRL_PERIODIC;
    } else if (mode == MODE_ONESHOT) {
        val |= TIMER_CTRL_ONESHOT;
    } else { /* mode is periodic */
        val &= ~TIMER_CTRL_ONESHOT;
        val |= TIMER_CTRL_PERIODIC;
    }

    u_secs = usecs & 0xFFFFFFFF; /* only low 32bit is valid */
    write32((uintptr_t)(timer_base + TIMER_CTRL + reg_offset), val);
    write32((uintptr_t)(timer_base + TIMER_LOAD + reg_offset), u_secs);
}

uint64_t timer_free_running_value_get(void)
{
    uint64_t time;
    uint64_t result;

    time = timer_get_value(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
    if (time == TIMER_VALUE_INVALID)
        return TIMER_VALUE_INVALID;

    result = (time <= TIMER_COUNT_MAX) ? (TIMER_COUNT_MAX - time) : 0;
    return result;
}

void timer_enable(uint32_t timer_base, uint32_t tim_mod_index)
{
    uint32_t ctrl;
    uint32_t reg_offset;

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
    uint32_t ctrl;

    ctrl = read32(SCCLKCNTCFG);
    hm_debug("read kcntcfg = 0x%x\n", ctrl);
    ctrl |= TIMER_SECU_EN;
    write32(SCCLKCNTCFG, ctrl);
}

void set_timer_non_secure(void)
{
    uint32_t ctrl;

    ctrl = read32(SCCLKCNTCFG);
    hm_debug("read kcntcfg = 0x%x\n", ctrl);
    ctrl &= (~TIMER_SECU_EN); /* timer10 */
    write32(SCCLKCNTCFG, ctrl);
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

void save_freerunning_timer(uint32_t flag)
{
    /* only armpc platform can receive S4 messages now */
    if (flag != TIMER_SUSPEND_S4)
        return;

    g_free_time_val = timer_get_value(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
    if (g_free_time_val == TIMER_VALUE_INVALID)
        hm_error("free time clear or reg is just 0\n");

    g_syscounter_suspend = (uint64_t)timer_rtc_value_get();
    timer_disable(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
}

void resume_freerunning_timer(uint32_t flag)
{
    /* only armpc platform can receive S4 messages now */
    if (flag != TIMER_RESUME_S4)
        return;
    uint64_t free_time_now;
    uint64_t tmp;
    uint64_t syscounter_resume = timer_rtc_value_get();
    if (syscounter_resume >= g_syscounter_suspend) {
        g_suspend_time = syscounter_resume - g_syscounter_suspend;
    } else {
        hm_debug("timer reg reverse\n");
        g_suspend_time = TIMER_COUNT_MAX - g_syscounter_suspend + syscounter_resume;
    }

    tmp = g_suspend_time * TIMER_CLK_FREQ;
    if (g_suspend_time > (TIMER_COUNT_MAX / TIMER_CLK_FREQ)) {
        hm_error("suspend time too long, timer resume failed, assume resume 60 seconds\n");
        g_suspend_time = TIMER_S4_DEFAULT_PERIOD;
        tmp = TIMER_S4_DEFAULT_PERIOD * TIMER_CLK_FREQ;
    }

    if (g_free_time_val >= g_suspend_time) {
        free_time_now = g_free_time_val - tmp;
    } else {
        hm_debug("timer reg reverse\n");
        free_time_now = TIMER_COUNT_MAX - tmp + g_free_time_val;
    }

    timer_set_value(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM, MODE_FREE_RUNNING, free_time_now);
    timer_enable(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
}
