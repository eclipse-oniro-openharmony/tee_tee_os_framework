/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Irq function about timer
 * Create: 2019-08-20
 */

#include "timer_irq.h"
#include <stdio.h>
#include <sys/usrsyscall_ext.h>
#include <api/kcalls.h>
#include <drv_hwi_share.h>
#include <hmlog.h>
#include <drv_module.h>
#include <timer_reg.h>

#ifdef CONFIG_RTC_TIMER
#include <timer_rtc.h>
#endif

#include <timer_interrupt.h>
#include "timer_types.h"

#define KERNEL_MSG 1

struct irq_msg {
    hm_msg_header header;
    struct irq_msg_body body;
};

static uint32_t irq_dispatch_param_check(const struct hmcap_message_info *info)
{
    /* irq_msg can only be notification. */
    if ((info->msg_type != HM_MSG_TYPE_NOTIF) || (info->is_kernel_msg != KERNEL_MSG)) {
        hm_error("Error: msg type, it can only be notification from kernel\n");
        return TMR_DRV_ERROR;
    }

    if (info->msg_size != sizeof(struct irq_msg)) {
        hm_error("ERROR: msg size\n");
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

intptr_t irq_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info)
{
    struct irq_msg *req = NULL;
    uint32_t ret;

    /*
     * The register expect all functions have the paramter 'p_msg_hdl'.
     * Actually, this paramter is useless in this function.
     * But we cannot delete it.
     */
    (void)p_msg_hdl;

    if ((msg == NULL) || (info == NULL)) {
        hm_error("params is NULL\n");
        return TMR_DRV_ERROR;
    }

    ret = irq_dispatch_param_check(info);
    if (ret != TMR_DRV_SUCCESS)
        return TMR_DRV_ERROR;

    req = msg;
    switch (req->header.send.msg_id) {
#ifdef TIMER_EVENT_SUPPORT
    case TICK_TIMER_FIQ_NUMBLER:
        timer_oneshot_fiq_handler();
        ret = sys_hwi_enable(TICK_TIMER_FIQ_NUMBLER);
        if (ret != SRE_OK) {
            hm_error("tick timer failed\n");
            return TMR_DRV_ERROR;
        }
        break;
#endif

#if (defined CONFIG_RTC_TIMER) && (!defined SOFT_RTC_IRQ_DISABLE)
    case SECURE_RTC_FIQ_NUMBLER:
        timer_rtc_oneshot_fiq_handler();
        ret = sys_hwi_enable(SECURE_RTC_FIQ_NUMBLER);
        if (ret != SRE_OK) {
            hm_error("rtc timer failed\n");
            return TMR_DRV_ERROR;
        }
        break;
#endif

#ifndef TIMER_FREE_RUNNING_FIQ_DISABLE
    case FREE_RUNNING_FIQ_NUMBLER:
        timer_free_running_fiq_handler();
        ret = sys_hwi_enable(FREE_RUNNING_FIQ_NUMBLER);
        if (ret != SRE_OK) {
            hm_error("free running timer failed\n");
            return TMR_DRV_ERROR;
        }
        break;
#endif
    default:
        hm_error("TIMER Unknown timer irq number %u\n", req->header.send.msg_id);
        break;
    }

    return TMR_DRV_SUCCESS;
}
