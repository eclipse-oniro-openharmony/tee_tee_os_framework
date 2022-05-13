/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: anti root time api define in this file.
 * Create: 2022-04-22
 */

#include <sre_rwroot.h>
#include <root_status_ops.h>
#include <hmlog.h>
#include <tee_time_event.h>

static volatile uint32_t g_set_flag;
static timer_event *g_antiroot_event = NULL;

static void lib_tee_anti_root_handler(void *priv_data)
{
    int32_t ret;
    /*
     * The needs the handler has a 'void *' parameter.
     * So we should keep priv_data for compatible with other functions.
     */
    (void)priv_data;
    if (g_set_flag == 0) {
        uint32_t status = ((uint32_t)0x1 << ITIMEOUTBIT);
        ret = __SRE_WriteRootStatus(status);
        if (ret != TMR_OK)
            hm_error("antiroot: write root status error\n");
        else
            g_set_flag = 1;
    }
}

TEE_Result tee_antiroot_create_timer(uint32_t time_seconds)
{
    timeval_t set_time;
    int32_t timer_data = 0;
    uint32_t ret;
    timer_event *t_event = NULL;

    if (time_seconds <= TIMER_CREATE_SECONDS_THRESHOLD) {
        hm_error("timer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (g_antiroot_event != NULL) {
        hm_error("timer type already exist\n");
        return TEE_ERROR_BAD_STATE;
    }

    if (g_set_flag != 0) {
        hm_error("stop creat antitimer, only work once because of\n");
        return TEE_SUCCESS;
    }

    t_event = tee_time_event_create((sw_timer_event_handler)(lib_tee_anti_root_handler), TIMER_CLASSIC, &timer_data);
    if (t_event == NULL) {
        hm_error("failed to create timer event\n");
        return TEE_ERROR_TIMER_CREATE_FAILED;
    }

    g_antiroot_event   = t_event;
    set_time.tval.nsec = 0;
    set_time.tval.sec  = (int32_t)time_seconds;
    ret = tee_time_event_start(t_event, &set_time);
    if (ret != TEE_SUCCESS) {
        (void)tee_time_event_destroy(t_event);
        hm_error("start timer event failed\n");
        return TEE_ERROR_TIMER;
    }

    return TEE_SUCCESS;
}

TEE_Result tee_antiroot_destory_timer(void)
{
    uint32_t ret;
    if ((g_antiroot_event == NULL) && (g_set_flag == 1))
        return TEE_SUCCESS;

    if (g_antiroot_event == NULL) {
        hm_error("antiroot timer has been destory\n");
        return TEE_ERROR_TIMER;
    }

    /* stop timer may fail when timeout, no need to return */
    ret = tee_time_event_stop(g_antiroot_event);
    if (ret != TMR_OK)
        hm_warn("stop timer failed: cannot find the timer, ret=0x%x\n", ret);

    ret = tee_time_event_destroy(g_antiroot_event);
    if (ret != TMR_OK) {
        hm_error("destroy timer failed: cannot find the timer, ret=0x%x\n", ret);
        return TEE_ERROR_TIMER_DESTORY_FAILED;
    }

    g_antiroot_event = NULL;
    return TEE_SUCCESS;
}
