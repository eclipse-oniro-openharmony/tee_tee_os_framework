/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: Timer event api define in this file.
 * Create: 2022-01-07
 */

#include <pthread.h>
#include <securec.h>
#include <hmlog.h>
#ifdef CONFIG_LIB_TIMEMGR
#include <timemgr_api.h>
#endif
#include <api/errno.h>
#include <tee_mem_mgmt_api.h>
#include <sys/hm_syscall.h>
#include <sys/hmapi_ext.h>
#include <sys/usrsyscall_ext.h>
#include <tamgr_ext.h>
#include <timer.h>
#include <sys_timer.h>

#define INVALID_TIME_STAMP 0
#define MAX_VALUE_SIGNED_32BIT 0x7FFFFFFF

enum classic_timer_msg {
    CREATE_TIMER,
    START_TIMER,
    STOP_TIMER,
    DESTORY_TIMER,
    TIMER_OPS_SUCCESS,
    TIMER_OPS_FAIL,
};

struct timer_event_msg {
    hm_msg_header hdr;
};


int64_t timer_value_add(const timeval_t *time_val_1, const timeval_t *time_val_2)
{
    timeval_t time_val_sum;

    if (time_val_1 == NULL || time_val_2 == NULL) {
        hm_error("invlid param\n");
        return TIMEVAL_MAX;
    }

    if ((time_val_1->tval64 > 0 && time_val_2->tval64 > 0 && INT64_MAX - time_val_1->tval64 < time_val_2->tval64) ||
        (time_val_1->tval64 < 0 && time_val_2->tval64 < 0 && INT64_MIN - time_val_1->tval64 > time_val_2->tval64)) {
        hm_error("Time value add result overflow!\n");
        return TIMEVAL_MAX;
    }

    if ((time_val_1->tval.nsec >= NS_PER_SECONDS) || (time_val_2->tval.nsec >= NS_PER_SECONDS)) {
        hm_warn("timer value add:invalid nsec value\n");
        time_val_sum.tval.sec = time_val_1->tval.sec + time_val_2->tval.sec;
        time_val_sum.tval.nsec = 0;
    } else {
        time_val_sum.tval64 = time_val_1->tval64 + time_val_2->tval64;
        if (time_val_sum.tval.nsec > (NS_PER_SECONDS - 1)) {
            time_val_sum.tval.nsec -= NS_PER_SECONDS;
            time_val_sum.tval.sec += 1;
        }
    }

    return time_val_sum.tval64;
}

int64_t timer_value_sub(const timeval_t *time_val_1, const timeval_t *time_val_2)
{
    timeval_t time_val_sub;

    if ((time_val_1 == NULL) || (time_val_2 == NULL))
        return INVALID_TIME_STAMP;

    if ((time_val_1->tval64 > 0 && time_val_2->tval64 < 0 && INT64_MAX + time_val_2->tval64 < time_val_1->tval64) ||
        (time_val_1->tval64 < 0 && time_val_2->tval64 > 0 && INT64_MIN + time_val_2->tval64 > time_val_1->tval64)) {
        hm_error("Time value sub result overflow!\n");
        return INVALID_TIME_STAMP;
    }

    if ((time_val_1->tval.nsec >= NS_PER_SECONDS) || (time_val_2->tval.nsec >= NS_PER_SECONDS)) {
        hm_warn("timer value sub:invalid nsec value\n");
        time_val_sub.tval.sec = time_val_1->tval.sec - time_val_2->tval.sec;
        time_val_sub.tval.nsec = 0;
    } else {
        time_val_sub.tval64 = time_val_1->tval64 - time_val_2->tval64;
        if (time_val_sub.tval.nsec < 0)
            time_val_sub.tval.nsec += NS_PER_SECONDS;
    }

    return time_val_sub.tval64;
}

static uint32_t get_timeout_value(int32_t status, timer_event *t_event)
{
    uint32_t mills = HM_NO_TIMEOUT;
    timeval_t current_time;
    timeval_t expire_time;
    timeval_t diff_time;

    if (status == START_TIMER) {
        t_event->state = TIMER_STATE_ACTIVE;
        current_time.tval64 = SRE_ReadTimestamp();
        expire_time.tval64 = t_event->expires.tval64;
        diff_time.tval64 = timer_value_sub(&expire_time, &current_time);
        mills = diff_time.tval.sec * MS_PER_SECONDS + diff_time.tval.nsec / NS_PER_MSEC;
    }
    return mills;
}

static void classic_thread_reply(int32_t status, const timer_event *t_event, cref_t msg_hdl)
{
    int32_t ret;
    struct timer_event_msg rsp_msg = {{{ 0 }}};

    rsp_msg.hdr.send.msg_id = TIMER_OPS_SUCCESS;
    if (status == STOP_TIMER && t_event->state == TIMER_STATE_EXECUTING)
        rsp_msg.hdr.send.msg_id = TIMER_OPS_FAIL;

    ret = hm_msg_reply(msg_hdl, &rsp_msg, sizeof(rsp_msg));
    if (ret != TMR_OK)
        hm_error("classic timer reply fail\n");
}

static int32_t get_time_event_status(uint32_t state)
{
    int32_t status;
    if (state == TIMER_STATE_ACTIVE)
        status = START_TIMER;
    else if (state == TIMER_STATE_INACTIVE)
        status = STOP_TIMER;
    else if (state == TIMER_STATE_DESTROY)
        status = DESTORY_TIMER;
    else
        status = CREATE_TIMER;
    return status;
}

static void *classic_thread(void *arg)
{
    int32_t ret;
    uint32_t mills = HM_NO_TIMEOUT;
    int32_t status = CREATE_TIMER;
    timer_event *t_event = (timer_event*)arg;
    struct channel_ipc_args ipc_args = { 0 };
    struct timer_event_msg req_msg = {{{ 0 }}};

    if (t_event == NULL) {
        hm_error("invalid timer event\n");
        return NULL;
    }

    cref_t msg_hdl = hmapi_create_message();
    if (is_ref_err(msg_hdl)) {
        hm_error("create message failed\n");
        return NULL;
    }

    t_event->pid = (int32_t)get_selfpid();
    ipc_args.channel = t_event->timer_channel;
    ipc_args.recv_buf = &req_msg;
    ipc_args.recv_len = sizeof(req_msg);
    while (status != DESTORY_TIMER) {
        ret = hmapi_recv_timeout(&ipc_args, &msg_hdl, CREF_NULL, mills, NULL);
        if (ret != TMR_OK && ret != E_EX_TIMER_TIMEOUT) {
            (void)hmapi_delete_obj(msg_hdl);
            return NULL;
        }

        if (ret == E_EX_TIMER_TIMEOUT && t_event->state == TIMER_STATE_ACTIVE && t_event->handler != NULL) {
            t_event->state = TIMER_STATE_EXECUTING;
            t_event->handler(t_event->data);
            status = get_time_event_status(t_event->state);
        } else if (ret == TMR_OK) {
            status = req_msg.hdr.send.msg_id;
        }

        mills = get_timeout_value(status, t_event);
        if (status == START_TIMER)
            t_event->state = TIMER_STATE_ACTIVE;
        else if (status == STOP_TIMER && t_event->state != TIMER_STATE_EXECUTING)
            t_event->state = TIMER_STATE_INACTIVE;

        if (ret == TMR_OK)
            classic_thread_reply(status, t_event, msg_hdl);
    }

    ret = hmapi_delete_obj(msg_hdl);
    if (ret != TMR_OK)
        hm_error("delete obj failed!\n");
    return NULL;
}

static uint32_t classic_thread_create(timer_event *t_event)
{
    pthread_attr_t thread_attr;
    int32_t ret;
    pthread_t thread_id;

    ret = pthread_attr_init(&thread_attr);
    if (ret != TMR_OK) {
        hm_error("init failed %d\n", ret);
        return ret;
    }

    /* set the timer_event thread's ca to zero */
    ret = pthread_attr_settee(&thread_attr, TEESMP_THREAD_ATTR_CA_WILDCARD, TEESMP_THREAD_ATTR_TASK_ID_INHERIT,
                              TEESMP_THREAD_ATTR_HAS_SHADOW);
    if (ret != TMR_OK) {
        (void)pthread_attr_destroy(&thread_attr);
        hm_error("setstacksize failed %d\n", ret);
        return ret;
    }

    ret = pthread_create(&thread_id, &thread_attr, classic_thread, t_event);
    if (ret != TMR_OK) {
        (void)pthread_attr_destroy(&thread_attr);
        hm_error("create failed %d\n", ret);
        return ret;
    }

    ret = pthread_attr_destroy(&thread_attr);
    if (ret != TMR_OK) {
        hm_error("destory failed: err=%d\n", ret);
        return ret;
    }

    return TMR_OK;
}

timer_event *tee_timer_event_create(sw_timer_event_handler handler, int32_t timer_class, void *priv_data)
{
    uint32_t ret;
    timer_event *t_event = NULL;
    cref_t timer_channel;

    if (handler == NULL || timer_class != TIMER_CLASSIC) {
        hm_error("bad parameters\n");
        return NULL;
    }

    t_event = TEE_Malloc(sizeof(*t_event), 0);
    if (t_event == NULL) {
        hm_error("no enough memory\n");
        return NULL;
    }

    timer_channel = hm_msg_channel_create();
    if (is_ref_err(timer_channel) != TMR_OK) {
        TEE_Free(t_event);
        return NULL;
    }

    t_event->timer_class = TIMER_CLASSIC;
    t_event->state = TIMER_STATE_INACTIVE;
    t_event->timer_channel = timer_channel;
    t_event->expires.tval64 = 0;
    t_event->handler = handler;
    t_event->data = priv_data;

    ret = classic_thread_create(t_event);
    if (ret != TMR_OK) {
        (void)hm_msg_channel_remove(t_event->timer_channel);
        TEE_Free(t_event);
        hm_error("create classic thread fail\n");
        return NULL;
    }

    return t_event;
}

uint32_t tee_timer_event_start(timer_event *t_event, timeval_t *time)
{
    uint32_t ret;
    timeval_t current_time;
    timeval_t expire_time;
    struct timer_event_msg req_msg = {{{ 0 }}};
    struct timer_event_msg rsp_msg = {{{ 0 }}};
    req_msg.hdr.send.msg_id = START_TIMER;

    if (t_event == NULL || time == NULL || t_event->timer_class != TIMER_CLASSIC) {
        hm_error("bad parameters\n");
        return TMR_ERR;
    }

    if ((time->tval.nsec > (NS_PER_SECONDS - 1)) || (time->tval.nsec < 0) ||
        ((uint32_t)(time->tval.sec) > MAX_VALUE_SIGNED_32BIT))
        return TMR_ERR;

    current_time.tval64 = SRE_ReadTimestamp();
    expire_time.tval64 = timer_value_add(&current_time, time);
    t_event->state = TIMER_STATE_ACTIVE;
    t_event->expires.tval64 = expire_time.tval64;

    if (t_event->pid == (int32_t)get_selfpid())
        return TMR_OK;

    ret = hm_msg_call(t_event->timer_channel, &req_msg, sizeof(req_msg), &rsp_msg, sizeof(rsp_msg), 0, HM_NO_TIMEOUT);
    if (ret != TMR_OK || rsp_msg.hdr.send.msg_id != TIMER_OPS_SUCCESS) {
        ret = TMR_ERR;
        hm_error("start timer event fail\n");
    }

    return ret;
}

uint32_t tee_timer_event_stop(timer_event *t_event)
{
    uint32_t ret;
    struct timer_event_msg req_msg = {{{ 0 }}};
    struct timer_event_msg rsp_msg = {{{ 0 }}};
    req_msg.hdr.send.msg_id = STOP_TIMER;

    if (t_event == NULL || t_event->timer_class != TIMER_CLASSIC) {
        hm_error("bad parameters\n");
        return TMR_ERR;
    }

    if (t_event->state != TIMER_STATE_ACTIVE)
        return TMR_ERR;

    t_event->state = TIMER_STATE_INACTIVE;
    if (t_event->pid == (int32_t)get_selfpid())
        return TMR_OK;

    ret = hm_msg_call(t_event->timer_channel, &req_msg, sizeof(req_msg), &rsp_msg, sizeof(rsp_msg), 0, HM_NO_TIMEOUT);
    if (ret != TMR_OK || rsp_msg.hdr.send.msg_id != TIMER_OPS_SUCCESS) {
        ret = TMR_ERR;
        hm_error("stop timer event fail\n");
    }

    return ret;
}

uint32_t tee_timer_event_destroy(timer_event *t_event)
{
    int32_t ret;
    struct timer_event_msg req_msg = {{{ 0 }}};
    struct timer_event_msg rsp_msg = {{{ 0 }}};
    req_msg.hdr.send.msg_id = DESTORY_TIMER;

    if (t_event == NULL) {
        hm_error("bad parameters\n");
        return TMR_ERR;
    }

    if (t_event->state != TIMER_STATE_INACTIVE && t_event->state != TIMER_STATE_EXECUTING) {
        hm_error("invalid timer event state %d\n", t_event->state);
        return TMR_ERR;
    }

    if (t_event->pid == (int32_t)get_selfpid()) {
        ret = TMR_OK;
    } else {
        ret = hm_msg_call(t_event->timer_channel, &req_msg, sizeof(req_msg),
                          &rsp_msg, sizeof(rsp_msg), 0, HM_NO_TIMEOUT);
        if (ret != TMR_OK || rsp_msg.hdr.send.msg_id != TIMER_OPS_SUCCESS)
            hm_error("stop timer event fail\n");
    }

    if (hm_msg_channel_remove(t_event->timer_channel))
        hm_error("channel remove failed\n");

    (void)memset_s(t_event, sizeof(*t_event), 0, sizeof(*t_event));
    TEE_Free(t_event);
    return ret;
}

void release_timer_event_new(const TEE_UUID *uuid)
{
    (void)uuid;
    return;
}
