/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Rtc timer functions
 * Create: 2021-05-27
 */
#include "timer_rtc.h"
#include <hmlog.h>
#include <register_ops.h>
#include <rtc_reg.h>
#include <timer_types.h>
#include <sre_hwi.h>

#define HWI_DEF_PRIORITY 0
#define INT_SECURE 0
#define INT_FUN_ARG 0x0
#define TIMER_INDEX_RTC   0

void rtc_timer_hardware_init(void)
{
    write32(RTC_CONTROL_REG, RTC_CTL_ENABLE);
    write32(RTC_IMSC, RTC_INT_DISABLE);
}

uint32_t timer_rtc_value_get(void)
{
    return read32(RTC_DATA_REG);
}

void timer_rtc_reset(uint32_t value)
{
    uint32_t cur_time;
    uint32_t new_time;

    cur_time = timer_rtc_value_get();
    new_time = value + cur_time;
    if ((new_time <= value) || (new_time <= cur_time)) {
        hm_error("integer overflow, set value is 0x%x, cur_time is 0x%x\n", value, cur_time);
        return;
    }

    write32(RTC_MATCH_REG, new_time);
    /* clear interupt */
    write32(RTC_ICR, RTC_INT_CLEAR);
    /* enable rtc interrupt */
    write32(RTC_IMSC, RTC_INT_ENABLE);
}

void timer_rtc_oneshot_fiq_handler(void)
{
    /* clear interupt */
    write32(RTC_ICR, RTC_INT_CLEAR);
    timer_event_handler(TIMER_INDEX_RTC);
}

uint32_t rtc_timer_interrupt_init(void)
{
    uint32_t ret;

    ret = SRE_HwiCreate(SECURE_RTC_FIQ_NUMBLER, HWI_DEF_PRIORITY, INT_SECURE,
                        (HWI_PROC_FUNC)timer_rtc_oneshot_fiq_handler, INT_FUN_ARG);
    if (ret != SRE_OK) {
        hm_error("Create rtc one shot fiq handler failed!\n");
        return TMR_DRV_ERROR;
    }

    ret = SRE_HwiEnable(SECURE_RTC_FIQ_NUMBLER);
    if (ret != SRE_OK) {
        hm_error("Failed to enable hwi num=%d\n", SECURE_RTC_FIQ_NUMBLER);
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

uint32_t rtc_interrupt_resume(void)
{
    uint32_t ret;

    ret = SRE_HwiResume(SECURE_RTC_FIQ_NUMBLER, DEFAULT_HWI_PRI, INT_SECURE);
    if (ret != SRE_OK) {
        hm_error("resume irq %u failed\n", SECURE_RTC_FIQ_NUMBLER);
        return TMR_DRV_ERROR;
    }

    ret = SRE_HwiEnable(SECURE_RTC_FIQ_NUMBLER);
    if (ret != SRE_OK) {
        hm_error("enable irq %u failed\n", SECURE_RTC_FIQ_NUMBLER);
        return TMR_DRV_ERROR;
    }

    return ret;
}

void timer_tick_trigger(uint64_t clock_cycles)
{
    timer_rtc_reset((uint32_t)clock_cycles);
}

void timer_disable(void)
{
    /* nothing to do */
}