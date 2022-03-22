/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Interrupt functions belong to timer
 * Create: 2019-08-20
 */
#include "timer_interrupt.h"
#include <hmlog.h>
#include <sre_hwi.h>
#include <drv_module.h>
#include <secure_gic_common.h>
#include <register_ops.h>
#include <timer_event.h>

#ifdef CONFIG_RTC_TIMER
#include <timer_rtc.h>
#endif

#include <timer_reg.h>
#include <timer_types.h>
#include "timer_sys.h"
#include "timer_hw.h"

#define HWI_DEF_PRIORITY 0
#define DEFAULT_HWI_PRI 0
#define INT_FUN_ARG 0x0
#define RTC_INIT_TIME 0x0

static const uint32_t g_timer_hwi[] = {
#ifndef TIMER_FREE_RUNNING_FIQ_DISABLE
    FREE_RUNNING_FIQ_NUMBLER,
#endif
#ifdef TIMER_EVENT_SUPPORT
    TICK_TIMER_FIQ_NUMBLER,
#endif
#if (defined CONFIG_RTC_TIMER) && (!defined SOFT_RTC_IRQ_DISABLE)
    SECURE_RTC_FIQ_NUMBLER,
#endif
};

void timer_free_running_fiq_handler(void)
{
#ifndef TIMER_FREE_RUNNING_FIQ_DISABLE
    uint32_t ret;

    ret = secure_timer_mis_read(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
    if (ret != TIMER_VALUE_INVALID) {
        secure_timer_irq_clear(FREE_RUNNING_TIMER_BASE, FREE_RUNNING_TIMER_NUM);
        hm_debug("in Freerunning timer handler!\n");
        timer_free_running_value_set();
    }
#endif
}

void timer_oneshot_fiq_handler(void)
{
#ifdef TIMER_EVENT_SUPPORT
    uint32_t ret;

    ret = secure_timer_mis_read(TICK_TIMER_BASE, TICK_TIMER_NUM);
    if (ret != TIMER_VALUE_INVALID) {
        secure_timer_irq_clear(TICK_TIMER_BASE, TICK_TIMER_NUM);
        hm_debug("in Oneshot timer handler!\n");

        /* for soft_rtc, we need handle both rtc timer and tick timer */
#ifdef SOFT_RTC_TICK
        timer_event_handler(TIMER_INDEX_RTC);
#endif
        timer_event_handler(TIMER_INDEX_TIMER);
    }
#endif
}

uint32_t timer_interrupt_enable_all(void)
{
    uint32_t i;
    uint32_t ret;

    /*
     * GIC distributor has already been enabled by platdrv,
     * so there is no need to invoke secure_distributor_enable()
     */
    for (i = 0; i < ARRAY_SIZE(g_timer_hwi); i++) {
        ret = SRE_HwiEnable(g_timer_hwi[i]);
        if (ret != SRE_OK) {
            hm_error("enable irq %u failed\n", g_timer_hwi[i]);
            return TMR_DRV_ERROR;
        }
    }

    return TMR_DRV_SUCCESS;
}

uint32_t timer_hwi_resume_all(void)
{
    uint32_t i;
    uint32_t ret;

    /* When S/R gic registers changed, so set the target cpu when resume */
    for (i = 0; i < ARRAY_SIZE(g_timer_hwi); i++) {
        ret = SRE_HwiResume(g_timer_hwi[i], DEFAULT_HWI_PRI, INT_SECURE);
        if (ret != TMR_DRV_SUCCESS) {
            hm_error("resume irq %u failed\n", g_timer_hwi[i]);
            return TMR_DRV_ERROR;
        }
    }

    return TMR_DRV_SUCCESS;
}

static uint32_t secure_timer_handler_init(void)
{
    uint32_t ret;

#ifndef TIMER_FREE_RUNNING_FIQ_DISABLE
    ret = SRE_HwiCreate(FREE_RUNNING_FIQ_NUMBLER, HWI_DEF_PRIORITY, INT_SECURE,
                        (HWI_PROC_FUNC)timer_free_running_fiq_handler, INT_FUN_ARG);
    if (ret != SRE_OK) {
        hm_error("Create Free Running failed!\n");
        return TMR_DRV_ERROR;
    }
#endif

#ifdef TIMER_EVENT_SUPPORT
    ret = SRE_HwiCreate(TICK_TIMER_FIQ_NUMBLER, HWI_DEF_PRIORITY, INT_SECURE,
                        (HWI_PROC_FUNC)timer_oneshot_fiq_handler, INT_FUN_ARG);
    if (ret != SRE_OK) {
        hm_error("Create one shot fiq handler failed!\n");
        return TMR_DRV_ERROR;
    }
#endif

#if (defined CONFIG_RTC_TIMER) && (!defined SOFT_RTC_IRQ_DISABLE)
    ret = SRE_HwiCreate(SECURE_RTC_FIQ_NUMBLER, HWI_DEF_PRIORITY, INT_SECURE,
                        (HWI_PROC_FUNC)timer_rtc_oneshot_fiq_handler, INT_FUN_ARG);
    if (ret != SRE_OK) {
        hm_error("Create rtc one shot fiq handler failed!\n");
        return TMR_DRV_ERROR;
    }
#endif
    (void)ret;
    return TMR_DRV_SUCCESS;
}

static uint32_t secure_timer_interrupt_enable(void)
{
    uint32_t ret;

    /* enable GIC */
#ifndef TIMER_FREE_RUNNING_FIQ_DISABLE
    ret = SRE_HwiEnable(FREE_RUNNING_FIQ_NUMBLER);
    if (ret != SRE_OK) {
        hm_error("Failed to enable hwi num=%d\n", FREE_RUNNING_FIQ_NUMBLER);
        return TMR_DRV_ERROR;
    }
#endif

#ifdef TIMER_EVENT_SUPPORT
    ret = SRE_HwiEnable(TICK_TIMER_FIQ_NUMBLER);
    if (ret != SRE_OK) {
        hm_error("Failed to enable hwi num=%d\n", TICK_TIMER_FIQ_NUMBLER);
        return TMR_DRV_ERROR;
    }
#endif

#ifdef CONFIG_RTC_TIMER
#ifndef SOFT_RTC_IRQ_DISABLE
    ret = SRE_HwiEnable(SECURE_RTC_FIQ_NUMBLER);
    if (ret != SRE_OK) {
        hm_error("Failed to enable hwi num=%d\n", SECURE_RTC_FIQ_NUMBLER);
        return TMR_DRV_ERROR;
    }
#endif

    timer_rtc_init();
#endif
    (void)ret;
    return TMR_DRV_SUCCESS;
}

uint32_t timer_interrupt_init(void)
{
    uint32_t ret;

    timer_cpu_info_init();
    timer_clk_init();

    ret = secure_timer_handler_init();
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("sectime init failed!\n");
        return TMR_DRV_ERROR;
    }

    timer_free_running_enable();
    ret = secure_timer_interrupt_enable();
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("sectime interrupt failed!\n");
        return TMR_DRV_ERROR;
    }

    init_startup_time_kernel(RTC_INIT_TIME);
    hm_debug("timer fiq enable and rtc init ok\n");
    return TMR_DRV_SUCCESS;
}
