/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Main function in timer
 * Create: 2019-08-20
 */

#include <stdio.h>
#include <timer.h>
#include <errno.h>
#include <bootinfo_types.h>
#include <cs.h>
#include <sys/usrsyscall_ext.h>
#include <ipclib.h>
#include <ac.h>
#include <sys/hmapi_ext.h>
#include <tamgr_ext.h>
#include <ta_permission.h>
#include <irqmgr_api_ext.h>
#include <sys/hm_priorities.h>

#include <hmlog.h>
#include "timer_irq.h"
#include "timer_init.h"
#include "timer_types.h"

const char *g_debug_prefix = "[===> DRV_TIMER <===]";

static int32_t hm_system_init(cref_t *timer_channel)
{
    int32_t ret;

    ret = hm_create_ipc_native(TIMER_PATH, timer_channel);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("failed to create channel with name \"%s\":%d\n", TIMER_PATH, ret);
        return TMR_DRV_ERROR;
    }

    ret = hm_tcb_set_priority(hm_tcb_get_cref(), HM_PRIO_KERNEL_TIMER);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("failed to set priority\n");
        return TMR_DRV_ERROR;
    }

    ret = ac_init(hmapi_cnode_cref(), hmapi_get_sysmgrch(), TIMER_PATH);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("failed to initialize libac\n");
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

__attribute__((visibility("default"))) int32_t main(void)
{
    cref_t timer_channel;
    int32_t ret;
    dispatch_fn_t dispatch_fns[] = {
        [HM_MSG_HEADER_CLASS_TMRMGR] = timer_dispatch,
        [HM_MSG_HEADER_CLASS_IRQMGR] = irq_dispatch,
        [HM_MSG_HEADER_CLASS_ACMGR_PUSH] = ac_dispatch,
    };

    ret = hm_system_init(&timer_channel);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("failed to init timer channel: %d\n", ret);
        return TMR_DRV_ERROR;
    }

    ret = timer_init(timer_channel);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("failed to init timer subsystem: %d\n", ret);
        return TMR_DRV_ERROR;
    }

    ret = hm_tamgr_register("drv_timer");
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("tamgr registration for timer failed\n");
        return TMR_DRV_ERROR;
    }

    ret = ta_permission_init();
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("ta init failed\n");
        return TMR_DRV_ERROR;
    }

    hm_debug("start server loop for channel 0x%llx\n", timer_channel);
    cs_server_loop(timer_channel, dispatch_fns, ARRAY_SIZE(dispatch_fns), NULL, NULL);

    return TMR_DRV_SUCCESS;
}
