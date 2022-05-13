/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: rtc timer init function
 * Create: 2021-05-27
 */
#include "rtc_timer_init.h"
#include <timer_types.h>
#include <drv_module.h>
#include <rtc_timer_syscall.h>
#include <rtc_timer_pm.h>
#include <timer_sys.h>
#include <timer_rtc.h>
#include <hmlog.h>

int32_t rtc_timer_init(void)
{
    int32_t ret;

    timer_cpu_info_init();
    rtc_timer_hardware_init();

    /* register rtc irq */
    ret = rtc_timer_interrupt_init();
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("init rtc interrupt fail\n");
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

DECLARE_TC_DRV(
    rtc_timer,
    0,
    rtc_timer_suspend,
    rtc_timer_resume,
    TC_DRV_MODULE_INIT,
    rtc_timer_init,
    NULL,
    rtc_timer_syscall,
    rtc_timer_suspend,
    rtc_timer_resume
);