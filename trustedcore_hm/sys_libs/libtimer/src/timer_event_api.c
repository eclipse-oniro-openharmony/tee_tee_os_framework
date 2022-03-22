/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Timer event api define in this file.
 * Create: 2019-08-20
 */
#include "timer_event_api.h"

#include <pthread.h>
#include <sys/usrsyscall_ext.h>
#include <sys/hm_priorities.h>
#include <sys/hm_syscall.h>
#include <sys/hmapi_ext.h>
#include <securec.h>
#include <errno.h>
#include <hmlog.h>
#include <hm_unistd.h>
#include <inttypes.h>
#include <ipclib.h>
#include <api/kcalls.h>
#include <posix_types.h>
#include <pathmgr_ext.h>
#include <tee_inner_uuid.h>
#include <api/errno.h>
#ifdef CONFIG_LIB_TIMEMGR
#include <timemgr_api.h>
#endif
#include "sys_timer.h"
#include "tee_inner_uuid.h"
#include "mem_ops_ext.h"
#ifdef CONFIG_LIB_TIMEMGR
#include <timemgr_api.h>
#endif

#define IPC_NAME_MAX    32
#define TIMER_EVENT_MAX 32
#define DESTROY_MSG_ID  0xdead
/* default pthread stack size: 8K */
#define PTHREAD_DEFAULT_STACK_SIZE 8192

static TEE_UUID g_drv_timer_uuid = TEE_DRV_TIMER;

enum timer_event_thread_status_t { TIMER_EVENT_THREAD_NONE = 0, TIMER_EVENT_THREAD_CREATE, TIMER_EVENT_THREAD_DESTROY };

struct timer_event_msg_t {
    hm_msg_header hdr;
    uint32_t app_handler;
};

#ifndef CONFIG_OFF_DRV_TIMEMGR
static volatile enum timer_event_thread_status_t g_timer_thread_status;
static pthread_t g_timer_event_thread;
static pthread_mutex_t g_timer_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_timer_handler_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * we need to support multiple timer event in one app, g_timer_event_refcnt is used
 * to track when we should delete the g_timer_event_thread
 */
static volatile uint32_t g_timer_event_refcnt;
static cref_t g_timer_channel;
static cref_t g_cnode_idx;
static char g_timer_name[IPC_NAME_MAX];
static struct sw_timer_event_hdl_info g_timer_event_hdl[TIMER_EVENT_MAX];
static timer_event *g_timer_event_arr[TIMER_EVENT_MAX];

static uint32_t acquire_hdl_slot(const sw_timer_event_handler handler, void *priv_data)
{
    uint32_t i;
    int32_t ret;

    ret = pthread_mutex_lock(&g_timer_handler_mutex);
    if (ret != TMR_OK) {
        hm_error("get timer handler mutex failed!\n");
        return TIMER_EVENT_MAX;
    }

    for (i = 0; i < TIMER_EVENT_MAX; i++) {
        if (g_timer_event_hdl[i].hdl  == NULL) {
            g_timer_event_hdl[i].hdl = handler;
            g_timer_event_hdl[i].priv_data = priv_data;

            ret = pthread_mutex_unlock(&g_timer_handler_mutex);
            if (ret != TMR_OK)
                hm_error("release timer handler mutex failed!\n");
            return i;
        }
    }

    ret = pthread_mutex_unlock(&g_timer_handler_mutex);
    if (ret != TMR_OK)
        hm_error("release timer handler mutex failed!\n");

    return TIMER_EVENT_MAX;
}

static int32_t release_hdl_slot(uint32_t idx)
{
    int32_t ret;

    if (idx >= TIMER_EVENT_MAX) {
        hm_error("idx is overflow, idx = %u\n", idx);
        return TMR_ERR;
    }

    ret = pthread_mutex_lock(&g_timer_handler_mutex);
    if (ret != TMR_OK) {
        hm_error("get timer handler mutex failed!\n");
        return TMR_ERR;
    }

    if (g_timer_event_hdl[idx].hdl != NULL) {
        g_timer_event_hdl[idx].hdl = NULL;
        g_timer_event_hdl[idx].priv_data = NULL;
        g_timer_event_arr[idx] = NULL;
    }

    ret = pthread_mutex_unlock(&g_timer_handler_mutex);
    if (ret != TMR_OK) {
        hm_error("release timer handler mutex failed!\n");
        return TMR_ERR;
    }

    return TMR_OK;
}

static uint32_t get_hdl_from_timer_event(const timer_event *event)
{
    uint32_t i;

    for (i = 0; i < TIMER_EVENT_MAX; i++) {
        if (g_timer_event_arr[i] == event)
            return i;
    }
    return TIMER_EVENT_MAX;
}

static uint32_t timer_event_handle(uint32_t idx)
{
    int32_t ret;
    struct sw_timer_event_hdl_info timer_event_hdl;

    ret = pthread_mutex_lock(&g_timer_handler_mutex);
    if (ret != TMR_OK) {
        hm_error("get timer handler mutex failed!\n");
        return TMR_ERR;
    }

    if (g_timer_event_hdl[idx].hdl != NULL) {
        timer_event_hdl.hdl = g_timer_event_hdl[idx].hdl;
        timer_event_hdl.priv_data = g_timer_event_hdl[idx].priv_data;
        ret = pthread_mutex_unlock(&g_timer_handler_mutex);
        if (ret != TMR_OK) {
            hm_error("release timer handler mutex failed!\n");
            return TMR_ERR;
        }
        timer_event_hdl.hdl(timer_event_hdl.priv_data);
    } else {
        hm_error("failed to find handler for idx 0x%x\n", idx);
        ret = pthread_mutex_unlock(&g_timer_handler_mutex);
        if (ret != TMR_OK)
            hm_error("release timer handler mutex failed!\n");
        return TMR_ERR;
    }

    return TMR_OK;
}

static uint32_t timer_msg_handler(uint32_t msg_id, const struct hmcap_message_info *info,
                                  const struct timer_event_msg_t *msg)
{
    uint32_t fiq_num = tick_timer_fiq_num_get();
    uint32_t ret;

    if (msg_id == fiq_num) {
        if (info->src_tcb_cref != timer_tcb_cref_get()) {
            hm_error("tick message from thirdparty\n");
            return TMR_ERR;
        }

        if ((msg->app_handler == 0) || (msg->app_handler > TIMER_EVENT_MAX)) {
            hm_error("handler is not valid\n");
            return TMR_ERR;
        } else {
            uint32_t idx = msg->app_handler - 1;
            if (idx >= TIMER_EVENT_MAX) {
                hm_error("timer event handler index is overflow %u\n", idx);
                return TMR_ERR;
            }

            ret = timer_event_handle(idx);
            if (ret != TMR_OK)
                return ret;
        }
    } else if (msg_id == DESTROY_MSG_ID) {
        /* terminate the thread when the sender is myself and the msg is destory */
        if (info->src_cnode_idx != g_cnode_idx) {
            hm_error("destroy message from thirdparty\n");
            return TMR_ERR;
        } else {
            g_timer_thread_status = TIMER_EVENT_THREAD_DESTROY;
        }
    } else {
        hm_error("unexpected msg id = %u\n", msg_id);
        return TMR_ERR;
    }

    return TMR_OK;
}

static void *wait_timer_event(void *arg)
{
    struct timer_event_msg_t msg   = { {{ 0 }}, 0 };
    struct hmcap_message_info info = { 0 };
    struct channel_ipc_args ipc_args = { 0 };
    uint32_t msg_id;
    int32_t ret;

    /* pthread_create needs a function pointer must have one 'void *' parameters */
    (void)arg;

    /* Give higher priority to avoid inexact time */
    ret = hmapi_set_priority(HM_PRIO_TEE_IRQHDLR);
    if (ret < 0) {
        hm_error("fail to set priority, ret = %d\n", ret);
        return NULL;
    }

    cref_t msg_hdl = hmapi_create_message();
    if (is_ref_err(msg_hdl) != TMR_OK) {
        hm_error("create message failed\n");
        return NULL;
    }

    ipc_args.channel = g_timer_channel;
    ipc_args.recv_buf = &msg;
    ipc_args.recv_len = sizeof(msg);
    while (g_timer_thread_status != TIMER_EVENT_THREAD_DESTROY) {
        ret = hmapi_recv_timeout(&ipc_args, &msg_hdl, CREF_NULL, HM_NO_TIMEOUT, &info);
        if (ret < 0) {
            hm_error("receive msg failed 0x%x\n", ret);
            (void)hmapi_delete_obj(msg_hdl);
            return NULL;
        }

        if ((info.msg_type != HM_MSG_TYPE_NOTIF) || (info.msg_size != sizeof(msg))) {
            hm_error("unexpected message type or size\n");
            continue;
        }
        msg_id           = msg.hdr.send.msg_id;
        uint32_t msg_ret = timer_msg_handler(msg_id, &info, &msg);
        if (msg_ret != TMR_OK) {
            (void)hmapi_delete_obj(msg_hdl);
            hm_error("msg handler failed 0x%x\n", msg_ret);
            return NULL;
        }
    }

    ret = hmapi_delete_obj(msg_hdl);
    if (ret != TMR_OK)
        hm_error("delete obj failed!\n");

    return NULL;
}

static uint32_t timer_event_thread_create(void)
{
    pthread_attr_t attr;
    int32_t ret;

    ret = pthread_attr_init(&attr);
    if (ret != TMR_OK) {
        hm_error("init failed %d\n", ret);
        return ret;
    }

    ret = pthread_attr_setstacksize(&attr, PTHREAD_DEFAULT_STACK_SIZE);
    if (ret != TMR_OK) {
        (void)pthread_attr_destroy(&attr);
        hm_error("setstacksize failed %d\n", ret);
        return ret;
    }

    /* set the timer_event thread's ca to zero */
    ret = pthread_attr_settee(&attr, TEESMP_THREAD_ATTR_CA_WILDCARD, TEESMP_THREAD_ATTR_TASK_ID_INHERIT,
                              TEESMP_THREAD_ATTR_NO_SHADOW);
    if (ret != TMR_OK) {
        (void)pthread_attr_destroy(&attr);
        hm_error("setstacksize failed %d\n", ret);
        return ret;
    }

    ret = pthread_create(&g_timer_event_thread, &attr, wait_timer_event, NULL);
    if (ret != TMR_OK) {
        (void)pthread_attr_destroy(&attr);
        hm_error("create failed %d\n", ret);
        return ret;
    }

    ret = pthread_attr_destroy(&attr);
    if (ret != TMR_OK) {
        hm_error("destory failed: err=%d\n", ret);
        return ret;
    }

    return TMR_OK;
}

static uint32_t timer_event_global_data_init(void)
{
    int size;
    pid_t timer_pid;

    /* setup the guard and make it visible to other cores */
    g_timer_thread_status = TIMER_EVENT_THREAD_CREATE;

    timer_pid = hm_getpid();
    if (timer_pid == HM_ERROR) {
        hm_error("failed to get pid\n");
        return TMR_ERR;
    }

    /* get the path `timer_[PID]` */
    size = snprintf_s(g_timer_name, sizeof(g_timer_name), sizeof(g_timer_name) - 1, "timer_%x", timer_pid);
    if (size <= 0) {
        hm_error("snprintf failed %d\n", size);
        g_timer_thread_status = TIMER_EVENT_THREAD_NONE;
        return TMR_ERR;
    }

    g_cnode_idx = hmapi_cnode_idx();
    if (g_cnode_idx == INVALID_CNODE_IDX) {
        hm_error("cnode index is invalid!\n");
        return TMR_ERR;
    }

    return TMR_OK;
}

static uint32_t create_timer_event_thread(void)
{
    uint32_t ret;
    int ipc_ret;

    /* make sure we only create just one timer event thread */
    if (g_timer_thread_status != TIMER_EVENT_THREAD_NONE) {
        g_timer_event_refcnt++;
        return TMR_OK;
    }

    ret = timer_event_global_data_init();
    if (ret != TMR_OK)
        return ret;

    g_timer_channel = hm_msg_channel_create();
    if (is_ref_err(g_timer_channel) != 0) {
        hm_error("create channel error 0x%" PRIx64 "\n", g_timer_channel);
        g_timer_thread_status = TIMER_EVENT_THREAD_NONE;
        return TMR_ERR;
    }

    /* register the channel with name `timer_[PID]` */
    ipc_ret = hm_ipc_register_ch_path(g_timer_name, g_timer_channel);
    if (ipc_ret != TMR_OK) {
        hm_error("register channel error %d\n", ipc_ret);
        ret = TMR_ERR;
        goto clear_channel;
    }

    /* the timer_event_thead is created by the first TimerEventCreate */
    g_timer_event_refcnt = 1;
    ret                  = timer_event_thread_create();
    if (ret != TMR_OK) {
        hm_error("timer event thread create failed!\n");
        goto clear_path;
    }

    return TMR_OK;

clear_path:
    g_timer_event_refcnt = 0;
    if (pathmgr_del_path(g_timer_name) != 0)
        hm_error("Remove %s from path_mgr failed\n", g_timer_name);
clear_channel:
    if (hm_msg_channel_remove(g_timer_channel))
        hm_error("channel remove failed\n");
    g_timer_channel = 0;

    return ret;
}

static int32_t timer_msg_notification(void)
{
    int32_t ret;

    /* send stop notification to g_timer_event_thread, msg_id = 0 indicate destory message */
    struct timer_event_msg_t msg = { {{ 0 }}, 0 };
    msg.hdr.send.msg_id          = (uint32_t)DESTROY_MSG_ID;
    ret                          = hm_msg_notification(g_timer_channel, &msg, sizeof(msg));
    if (ret != TMR_OK) {
        hm_error("notify failed!\n");
        return TMR_ERR;
    }

    ret = pthread_join(g_timer_event_thread, NULL);
    if (ret != TMR_OK) {
        hm_error("pthread join failed %d\n", ret);
        return TMR_ERR;
    }

    return TMR_OK;
}

static int32_t delete_timer_event_thread(void)
{
    int32_t ret;

    if (g_timer_event_refcnt > 1) {
        g_timer_event_refcnt--;
        return TMR_OK;
    }

    if (g_timer_channel == 0) {
        hm_error("timer event channel is invalid!\n");
        return TMR_ERR;
    }

    g_timer_event_refcnt = 0;
    ret                  = timer_msg_notification();
    if (ret != TMR_OK) {
        hm_error("timer message notification failed!\n");
        return TMR_ERR;
    }

    if (pathmgr_del_path(g_timer_name) != 0) {
        hm_error("Remove %s from path mgr failed\n", g_timer_name);
        return TMR_ERR;
    }

    if (hm_msg_channel_remove(g_timer_channel)) {
        hm_error("channel remove failed\n");
        return TMR_ERR;
    }
    g_timer_channel       = 0;
    g_timer_thread_status = TIMER_EVENT_THREAD_NONE;
    g_timer_event_thread  = 0;

    return TMR_OK;
}

static timer_event *timer_event_create(sw_timer_event_handler app_handler, int32_t timer_class, void *priv_data)
{
    uint32_t ret;

    struct timer_private_data_kernel *temp_priv_data = tee_alloc_sharemem_aux(&g_drv_timer_uuid,
        sizeof(struct timer_private_data_kernel));
    if (temp_priv_data == NULL) {
        hm_error("alloc private data sharemem failed\n");
        return NULL;
    }
    (void)memcpy_s(temp_priv_data, sizeof(struct timer_private_data_kernel), priv_data,
        sizeof(struct timer_private_data_kernel));

    uint64_t args[] = { (uint64_t)(uintptr_t)app_handler, (uint64_t)timer_class, (uint64_t)(uintptr_t)temp_priv_data };

    if (timer_class == TIMER_CLASSIC)
        /* in this mode, priv_data will be used in callback func, we should not send it to drv_timer */
        args[2] = 0;

    ret = hmtimer_call(SW_SYSCALL_TIMER_CREATE, args, ARRAY_SIZE(args));
    if ((ret != TMR_OK) && (g_timer_thread_status != TIMER_EVENT_THREAD_NONE)) {
        (void)tee_free_sharemem(temp_priv_data, sizeof(struct timer_private_data_kernel));
        temp_priv_data = NULL;
        return NULL;
    }

    (void)tee_free_sharemem(temp_priv_data, sizeof(struct timer_private_data_kernel));
    temp_priv_data = NULL;
    return (timer_event *)(uintptr_t)args[0];
}

static uint32_t classic_timer_event_create(const sw_timer_event_handler handler, void *priv_data, uint32_t *hdl)
{
    uint32_t ret;

    if (handler == NULL) {
        hm_error("type of timer event needs a handler\n");
        return TMR_ERR;
    }

    *hdl = acquire_hdl_slot(handler, priv_data);
    if (*hdl >= TIMER_EVENT_MAX) {
        hm_error("failed to acquire free slot\n");
        return TMR_ERR;
    }

    ret = create_timer_event_thread();
    if (ret != TMR_OK) {
        hm_error("timer event thread create failed: %u\n", ret);
        (void)release_hdl_slot(*hdl);
        return TMR_ERR;
    }

    return TMR_OK;
}

timer_event *timer_event_create_internal(sw_timer_event_handler handler, int32_t timer_class, void *priv_data)
{
    uint32_t hdl         = 0;
    uint64_t app_handler = (uint64_t)(uintptr_t)handler;
    timer_event *tevent  = NULL;
    uint32_t ret;
    int32_t lock_ret;

    lock_ret = pthread_mutex_lock(&g_timer_thread_mutex);
    if (lock_ret != TMR_OK) {
        hm_error("get timer thread mutex failed: %d\n", lock_ret);
        return NULL;
    }

    if (timer_class == TIMER_CLASSIC) {
        ret = classic_timer_event_create(handler, priv_data, &hdl);
        if (ret != TMR_OK) {
            hm_error("classic timer event create failed!\n");
            (void)pthread_mutex_unlock(&g_timer_thread_mutex);
            return NULL;
        }
        /*
         * plus 1 to avoid pass 0 to drv_timer, which will be considered
         * as an error
         */
        app_handler = hdl + 1;
    }

    tevent = timer_event_create((sw_timer_event_handler)(uintptr_t)app_handler, timer_class, priv_data);
    if (tevent == NULL) {
        hm_error("timer event create failed!\n");
        if (timer_class != TIMER_CLASSIC) {
            (void)pthread_mutex_unlock(&g_timer_thread_mutex);
            return NULL;
        }
        if (release_hdl_slot(hdl) != TMR_OK)
            hm_error("release hdl slot failed!\n");
        if (delete_timer_event_thread() != TMR_OK)
            hm_error("delete thread fail\n");
        (void)pthread_mutex_unlock(&g_timer_thread_mutex);

        return NULL;
    }

    /* save the timer_event pointer */
    if (timer_class == TIMER_CLASSIC)
        g_timer_event_arr[hdl] = tevent;

    lock_ret = pthread_mutex_unlock(&g_timer_thread_mutex);
    if (lock_ret != TMR_OK) {
        hm_error("release timer thread mutex failed: %d\n", lock_ret);
        return NULL;
    }

    return tevent;
}

uint32_t timer_event_destroy_internal(const timer_event *t_event)
{
    uint32_t ret;
    int32_t lock_ret;

    if (t_event == NULL) {
        hm_error("Bad parameters, event is null\n");
        return TMR_ERR;
    }

    lock_ret = pthread_mutex_lock(&g_timer_thread_mutex);
    if (lock_ret != TMR_OK) {
        hm_error("get timer thread mutex failed!\n");
        return TMR_ERR;
    }

    uint64_t hmcall_args[] = {
        (uint64_t)(uintptr_t)t_event,
    };
    ret = hmtimer_call(SW_SYSCALL_TIMER_DESTORY, hmcall_args, ARRAY_SIZE(hmcall_args));
    if (g_timer_thread_status != TIMER_EVENT_THREAD_NONE) {
        lock_ret = delete_timer_event_thread();
        if (lock_ret != TMR_OK)
            hm_error("failed to delete timer event!\n");

        uint32_t idx = get_hdl_from_timer_event((const timer_event *)t_event);
        if (idx >= TIMER_EVENT_MAX) {
            hm_error("failed to get slot from event\n");
        } else {
            if (release_hdl_slot(idx) != TMR_OK)
                hm_error("release hdl slot failed!\n");
        }
    }

    lock_ret = pthread_mutex_unlock(&g_timer_thread_mutex);
    if (lock_ret != TMR_OK) {
        hm_error("release timer thread mutex failed!\n");
        return TMR_ERR;
    }

    return ret;
}

void release_timer_event_internal(const TEE_UUID *uuid)
{
    uint32_t ret;

    TEE_UUID *temp_uuid = tee_alloc_sharemem_aux(&g_drv_timer_uuid, sizeof(TEE_UUID));
    if (temp_uuid == NULL) {
        hm_error("alloc temp_uuid sharemem failed\n");
        return;
    }
    (void)memcpy_s(temp_uuid, sizeof(TEE_UUID), uuid, sizeof(TEE_UUID));

    uint64_t hmcall_args[] = {
        (uint64_t)(uintptr_t)temp_uuid,
    };
    ret = hmtimer_call(SW_SYSCALL_RELEASE_TIMER_EVENT, hmcall_args, ARRAY_SIZE(hmcall_args));
    if (ret != TMR_OK)
        hm_error("release timer event failed\n");

    (void)tee_free_sharemem(temp_uuid, sizeof(TEE_UUID));
    temp_uuid = NULL;
}
#endif
