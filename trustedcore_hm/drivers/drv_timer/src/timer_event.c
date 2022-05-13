/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: timer event related functions defined in this file.
 * Create: 2019-08-20
 */
#include "timer_event.h"
#include <securec.h>
#include <sys/usrsyscall_ext.h>
#include <sys/usrsyscall_new_ext.h>
#include <hm_getpid.h>
#include <mem_ops.h>
#include <legacy_mem_ext.h>
#include <limits.h>
#include <ipclib.h>
#include <procmgr_ext.h>
#include <msg_ops.h>
#include <hmlog.h>
#include "drv_pal.h"
#include "timer_reg.h"
#include "timer_sys.h"
#include "timer_init.h"
#include "timer_hw.h"

#ifdef CONFIG_RTC_TIMER
#include "timer_rtc.h"
#endif

#include "timer_types.h"

#define GLOBAL_SERVICE_NAME "TEEGlobalTask"
#define TIMER60_NS_THRD     10000000

#define CPU_CORE_0 0
#define CALL_TA_DEFAULT_CMD 0
#define INVALID_TIME_STAMP 0

#define MAX_VALUE_SIGNED_32BIT 0x7FFFFFFF
#define MAX_GENERIC_TIMER_EVENT_NUM 32
#define MAX_CLASSIC_TIMER_EVENT_NUM 32
#define MAX_RTC_TIMER_EVENT_NUM 32
static struct timer_cpu_info g_timer_cpu_info;

struct timer_event_msg {
    hm_msg_header hdr;
    uint32_t app_handler;
};

static timer_event *timer_event_avail_get(const timer_event *event)
{
    struct timer_clock_info *clock_info = NULL;
    timer_event *temp = NULL;

    clock_info = &g_timer_cpu_info.clock_info[TIMER_INDEX_RTC];
    dlist_for_each_entry(temp, &clock_info->avail, timer_event, c_node) {
        if (temp->handle == (uint64_t)(uintptr_t)event)
            return temp;
    }

    clock_info = &g_timer_cpu_info.clock_info[TIMER_INDEX_TIMER];
    dlist_for_each_entry(temp, &clock_info->avail, timer_event, c_node) {
        if (temp->handle == (uint64_t)(uintptr_t)event)
            return temp;
    }

    return NULL;
}

uint32_t timer_event_destory_with_uuid(timer_event *timer_node, const struct tee_uuid *uuid, bool real_event)
{
    uint32_t ret;
    uint32_t len;

    if (timer_node == NULL || uuid == NULL) {
        hm_error("time node is null!\n");
        return TMR_DRV_ERROR;
    }

    if (!real_event) {
        timer_node = timer_event_avail_get(timer_node);
        if (timer_node == NULL) {
            hm_error("time node is not available!\n");
            return TMR_DRV_ERROR;
        }

        if (memcmp(uuid, &timer_node->timer_attr.uuid, sizeof(timer_node->timer_attr.uuid)) != 0) {
            hm_error("node is not belong to the uuid\n");
            return TMR_DRV_ERROR;
        }
    }

    if (timer_node->state != TIMER_STATE_INACTIVE) {
        hm_error("SW: Timer Event in USE :Cannot Free this Timer Event\n");
        return TMR_DRV_ERROR;
    }

    dlist_delete(&timer_node->c_node);

    len = strnlen(timer_node->path_name, IPC_NAME_MAX);
    if (len == IPC_NAME_MAX) {
        hm_error("invalid path_name, len overflow!\n");
        (void)SRE_MemFree(OS_MID_TIMER, timer_node);
        return TMR_DRV_ERROR;
    }

    if ((timer_node->timer_channel != 0) && (len != 0)) {
        ret = hm_ipc_release_path(timer_node->path_name, timer_node->timer_channel);
        if (ret != TMR_DRV_SUCCESS)
            hm_warn("release channel fail\n");
    }

    ret = SRE_MemFree(OS_MID_TIMER, timer_node);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("timer event destory with uuid,failed %u\n", ret);
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

static int32_t timer_rtc_wait_handler(void *priv_data)
{
    struct timer_private_data_kernel *timer_data = NULL;
    uint32_t ret;
    uint32_t gtask_handle;
    timer_event *timer_node = priv_data;

    if (timer_node == NULL) {
        hm_warn("timer_node is null!\n");
        return TMR_DRV_ERROR;
    }

    timer_data = &(timer_node->timer_attr);
    hm_debug("timer node uuid timerlow is 0x%x\n", timer_data->uuid.timeLow);
    hm_debug("timer node timer property type is 0x%x\n", timer_data->type);

    ret = ipc_hunt_by_name(CPU_CORE_0, GLOBAL_SERVICE_NAME, &gtask_handle);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("failed to get the name of task\n");
        return TMR_DRV_ERROR;
    }

    ret = ipc_msg_snd(CMD_TIMER_RTC, gtask_handle, timer_data, sizeof(*timer_data));
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("send msg failed\n");
        return TMR_DRV_ERROR;
    }

    gic_spi_notify();
    timer_node->state &= ~TIMER_STATE_EXECUTING;
    ret = timer_event_destory_with_uuid(timer_node, &(timer_node->timer_attr.uuid), true);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("destroy timer failed, ret = 0x%x\n", ret);
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

/*
 * NOTE: previously the timer handler are all in kernel space, thus when timer
 * expires we can invoke it directly.
 * However, in hmteeos the timer handler may located in other apps' vspace,
 * thus we need a wrapper to send a notify message to the app and it should
 * invoke the handler by itself (or encapsulate it in libtimer_a32).
 */
static int32_t timer_classic_wait_handler(void *priv_data)
{
    uint32_t ret;
    int32_t ipc_ret;
    timer_event *timer_node = priv_data;

    if (timer_node == NULL) {
        hm_error("time event is NULL!\n");
        return TMR_DRV_ERROR;
    }

    /* note we use `timer_[PID]` as the path_name to find app [PID]'s timer channel */
    if (snprintf_s(timer_node->path_name, sizeof(timer_node->path_name), sizeof(timer_node->path_name) - 1,
                   "timer_%x", timer_node->pid) <= 0) {
        hm_error("sprintf failed\n");
        return TMR_DRV_ERROR;
    }

    ipc_ret = hm_ipc_get_ch_from_path(timer_node->path_name, &(timer_node->timer_channel));
    if (ipc_ret != TMR_DRV_SUCCESS) {
        hm_error("get path %s failed\n", timer_node->path_name);
        return TMR_DRV_ERROR;
    }

    struct timer_event_msg msg = { {{ 0 }}, 0 };
    msg.hdr.send.msg_id = TICK_TIMER_FIQ_NUMBLER;
    msg.app_handler = timer_node->app_handler;
    ipc_ret = hm_msg_notification(timer_node->timer_channel, &msg, sizeof(msg));
    if (ipc_ret != TMR_DRV_SUCCESS) {
        hm_error("send notify message failed\n");
        return TMR_DRV_ERROR;
    }
    hm_yield();
    timer_node->state &= ~TIMER_STATE_EXECUTING;
    ret = hm_ipc_release_path(timer_node->path_name, timer_node->timer_channel);
    if (ret != TMR_DRV_SUCCESS)
        hm_warn("release channel fail\n");

    return TMR_DRV_SUCCESS;
}

static int32_t timer_generic_wait_handler(void *priv_data)
{
    uint32_t ret;
    struct timer_private_data_kernel *data = NULL;
    uint32_t gtask_handle = 0;
    timer_event *timer_node = priv_data;

    if (timer_node == NULL) {
        hm_error("time node is NULL!\n");
        return TMR_DRV_ERROR;
    }

    if (timer_node->callback_mode == TIMER_CALLBACK_TIMEOUT) {
        ret = ipc_msg_qsend(CALL_TA_DEFAULT_CMD, TIMER_CALLBACK_TIMEOUT, timer_node->pid,
                            (uint8_t)timer_node->timer_channel);
        if (ret != TMR_DRV_SUCCESS) {
            hm_error("msg Send for timeout failed\n");
            return TMR_DRV_ERROR;
        }

        timer_node->state &= ~TIMER_STATE_EXECUTING;
        return TMR_DRV_SUCCESS;
    }

    data = &timer_node->timer_attr;
    hm_info("step into time generic wait handler\n");
    ret = ipc_hunt_by_name(CPU_CORE_0, GLOBAL_SERVICE_NAME, &gtask_handle);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("failed to get global task handle\n");
        return TMR_DRV_ERROR;
    }

    ret = ipc_msg_snd(CMD_TIMER_GENERIC, gtask_handle, data, sizeof(*data));
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("send generic to global task failed\n");
        return TMR_DRV_ERROR;
    }

    /* Tell tzdriver to reschedule global task */
    gic_spi_notify();

    timer_node->state &= ~TIMER_STATE_EXECUTING;
    ret = timer_event_destory_with_uuid(timer_node, &(timer_node->timer_attr.uuid), true);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("destroy timer failed\n");
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
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

static void timer_event_queue_add(struct dlist_node *timer_queue_head, timer_event *timer_node)
{
    timer_event *temp = NULL;
    bool is_added = false;

    if (timer_queue_head->next == NULL) {
        hm_error("timer event queue add:null pointer was detected!\n");
        return;
    }

    if (dlist_empty(timer_queue_head)) {
        dlist_insert_head(&timer_node->node, timer_queue_head);
        is_added = true;
    } else {
        dlist_for_each_entry(temp, timer_queue_head, timer_event, node) {
            if (timer_node->expires.tval64 < temp->expires.tval64) {
                dlist_insert_tail(&timer_node->node, &temp->node);
                is_added = true;
                break;
            }
        }
    }

    if (is_added == false)
        dlist_insert_tail(&timer_node->node, timer_queue_head);

    timer_node->state = TIMER_STATE_ACTIVE;
}

static void timer_event_queue_del(timer_event *timer_node)
{
    dlist_delete(&timer_node->node);
    timer_node->state = TIMER_STATE_INACTIVE;
}

static struct dlist_node *timer_event_queue_next(const struct dlist_node *timer_queue_head)
{
    struct dlist_node *next = NULL;

    if (dlist_empty(timer_queue_head))
        next = NULL;
    else
        next = timer_queue_head->next;

    return next;
}

static bool timer_create_param_check(const sw_timer_event_handler handler, int32_t timer_class, const void *priv_data)
{
    bool invalid_param = ((timer_class == TIMER_CLASSIC) && (handler == NULL)) ||
                         ((timer_class != TIMER_CLASSIC) && (priv_data == NULL));
    if (invalid_param)
        return false;

    invalid_param = (timer_class < TIMER_GENERIC) || (timer_class > TIMER_CLASSIC);
    if (invalid_param) {
        hm_error("timer class is %d not supported\n", timer_class);
        return false;
    }

    return true;
}

static int32_t timer_event_handler_init(const sw_timer_event_handler handler, timer_event *new_event,
                                        int32_t timer_class, int32_t pid)
{
    if (timer_class == TIMER_RTC) {
        new_event->handler = timer_rtc_wait_handler;
    } else if (timer_class == TIMER_GENERIC) {
        new_event->handler = timer_generic_wait_handler;
    } else if (timer_class == TIMER_CLASSIC) {
        /*
         * if the timer is created by drv_timer, there is no need to
         * send msg again, just let drv_timer to handle the event.
         */
        if (pid == hm_getpid()) {
            new_event->handler = handler;
            new_event->app_handler = 0;
        } else {
            /* for TIMER_CLASSIC type of timer, we use this to send msg to the requester */
            new_event->app_handler = (uint32_t)(uintptr_t)handler;
            new_event->handler = timer_classic_wait_handler;
            new_event->timer_channel = 0;
        }
    } else {
        hm_error("Timer class is invalid!!!\n");
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

static int32_t timer_event_priv_data_init(timer_event *new_event, int32_t timer_class, const void *priv_data)
{
    errno_t ret_s;
    bool callback = false;

    if (timer_class == TIMER_CLASSIC)
        return TMR_DRV_SUCCESS;

    if (timer_class == TIMER_GENERIC) {
        const struct timer_private_data_kernel *priv = priv_data;
        /* Deal with timeout event */
        callback = (priv->dev_id <= 1) && (priv->session_id == 0) &&
                         (priv->type == TIMER_CALLBACK_TIMEOUT) &&
                         (priv->expire_time == 0);
        if (callback) {
            new_event->callback_mode = TIMER_CALLBACK_TIMEOUT;
            new_event->timer_channel = priv->dev_id;
        }
    }

    ret_s = memcpy_s(&(new_event->timer_attr), sizeof(new_event->timer_attr),
                     priv_data, sizeof(new_event->timer_attr));
    if (ret_s != EOK) {
        hm_error("timer event private data init: memcpy failed! ret_s is %d\n", ret_s);
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

static int32_t timer_event_init(const sw_timer_event_handler handler, int32_t timer_class, const void *priv_data,
                                timer_event *new_event, int32_t pid)
{
    errno_t ret_s;
    int32_t ret;
    spawn_uuid_t uuid;
    uint32_t timer_id = TIMER_INDEX_TIMER;
    uint32_t seed = get_mix_seed();
    uint32_t tmp_factor = (uint32_t)get_g_caller_pid();

    if (timer_class == TIMER_RTC)
        timer_id = TIMER_INDEX_RTC;

    new_event->clk_info = &g_timer_cpu_info.clock_info[timer_id];
    dlist_init(&new_event->node);
    dlist_init(&new_event->c_node);

    new_event->expires.tval64 = TIMEVAL_MAX;
    new_event->state = TIMER_STATE_INACTIVE;
    new_event->callback_mode = TIMER_CALLBACK_HARDIRQ;
    new_event->timer_class = timer_class;
    new_event->handle = ((uint64_t)(uintptr_t)new_event) ^ (seed ^ tmp_factor);
    new_event->pid = pid;

    ret = timer_event_handler_init(handler, new_event, timer_class, pid);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("timer event handler init failed!\n");
        return TMR_DRV_ERROR;
    }

    ret = timer_event_priv_data_init(new_event, timer_class, priv_data);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("timer event private data init failed!\n");
        return TMR_DRV_ERROR;
    }

    ret_s = hm_getuuid(pid, &uuid);
    if (ret_s != EOK) {
        hm_error("get uuid failed for pid = 0x%x\n", pid);
        return TMR_DRV_ERROR;
    }

    ret_s = memcpy_s(&(new_event->timer_attr.uuid), sizeof(new_event->timer_attr.uuid), &uuid.uuid, sizeof(uuid.uuid));
    if (ret_s != EOK) {
        hm_error("memcpy failed! ret  is %d\n", ret_s);
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

int32_t check_timer_event_max_num(int32_t timer_class, int32_t pid)
{
    errno_t ret_s;
    uint32_t timer_event_num = 0;
    uint32_t timer_id = TIMER_INDEX_TIMER;
    struct timer_clock_info *clock_info = NULL;
    timer_event *timer_node = NULL;
    spawn_uuid_t uuid;

    ret_s = hm_getuuid(pid, &uuid);
    if (ret_s != EOK) {
        hm_error("get uuid failed for pid = 0x%x\n", pid);
        return TMR_DRV_ERROR;
    }

    if (timer_class == TIMER_RTC)
        timer_id = TIMER_INDEX_RTC;

    clock_info = &g_timer_cpu_info.clock_info[timer_id];
    dlist_for_each_entry(timer_node, &clock_info->avail, timer_event, c_node) {
        if (timer_node->timer_class == timer_class &&
            memcmp(&uuid.uuid, (&timer_node->timer_attr.uuid), sizeof(timer_node->timer_attr.uuid)) == 0)
            timer_event_num++;
    }

    if (timer_class == TIMER_GENERIC) {
        if (timer_event_num < MAX_GENERIC_TIMER_EVENT_NUM)
            return TMR_DRV_SUCCESS;
    } else if (timer_class == TIMER_CLASSIC) {
        if (timer_event_num < MAX_CLASSIC_TIMER_EVENT_NUM)
            return TMR_DRV_SUCCESS;
    } else if (timer_class == TIMER_RTC) {
        if (timer_event_num < MAX_RTC_TIMER_EVENT_NUM)
            return TMR_DRV_SUCCESS;
    }

    return TMR_DRV_ERROR;
}

timer_event *timer_event_create(const sw_timer_event_handler handler, int32_t timer_class,
                                const void *priv_data, int32_t pid)
{
    timer_event *new_event = NULL;
    int32_t ret;
    errno_t ret_s;

    bool invalid_param = timer_create_param_check(handler, timer_class, priv_data);
    if (invalid_param == false)
        return NULL;

    ret = check_timer_event_max_num(timer_class, pid);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("max timer event num limits, timer class is %d\n", timer_class);
        return NULL;
    }

    new_event = (timer_event *)SRE_MemAlloc(OS_MID_TIMER, OS_MEM_DEFAULT_FSC_PT, sizeof(*new_event));
    if (new_event == NULL) {
        hm_error("SW: Malloc failed in Creating New Timer event\n");
        return NULL;
    }

    ret_s = memset_s(new_event, sizeof(*new_event), 0, sizeof(*new_event));
    if (ret_s != EOK) {
        hm_error("memset failed!\n");
        (void)SRE_MemFree(OS_MID_TIMER, new_event);
        return NULL;
    }

    ret = timer_event_init(handler, timer_class, priv_data, new_event, pid);
    if (ret != 0) {
        hm_error("timer event init failed! ret is %d\n", ret);
        (void)SRE_MemFree(OS_MID_TIMER, new_event);
        return NULL;
    }

    if (new_event->clk_info == NULL) {
        hm_error("new event clock info is NULL\n");
        (void)SRE_MemFree(OS_MID_TIMER, new_event);
        return NULL;
    }
    dlist_insert_head(&new_event->c_node, &new_event->clk_info->avail);

    return (timer_event *)(uintptr_t)new_event->handle;
}

static void timer_expire_value_set(timer_event *timer_node, const timeval_t *expire_value)
{
    timer_node->expires = *expire_value;
    hm_debug("set expire sec is %d, nsec is %d\n", timer_node->expires.tval.sec, timer_node->expires.tval.nsec);
}

int64_t timer_expire_value_get(const timer_event *timer_node, bool real_event)
{
    if (real_event == false)
        timer_node = timer_event_avail_get(timer_node);

    if (timer_node == NULL)
        return TIMEVAL_MAX;

    return timer_node->expires.tval64;
}

int64_t timer_expire_get(const timer_event *timer_node)
{
    if (timer_node == NULL)
        return TIMEVAL_MAX;

    return timer_expire_value_get(timer_node, false);
}

static void timer_tick_trigger(uint64_t usecs, int32_t timer_class)
{
    if (usecs < TIMER_COUNT_MIN) {
        hm_warn("SW: one shot time minimum value should be 1 us\n");
        usecs = TIMER_COUNT_MIN;
    }

    if (is_tick_timer(timer_class)) {
        timer_set_value(TICK_TIMER_BASE, TICK_TIMER_NUM, MODE_ONESHOT, usecs);
        timer_enable(TICK_TIMER_BASE, TICK_TIMER_NUM);
    } else if (timer_class == TIMER_RTC) {
#ifdef CONFIG_RTC_TIMER
        timer_rtc_reset((uint32_t)usecs);
#endif
    } else {
        hm_warn("time class %d is invalid!\n", timer_class);
    }
}

static void timer_tick_event(int64_t expires_time, int32_t timer_class)
{
    timeval_t time_next_tick;
    uint64_t clock_cycles;
    timeval_t expires;
    timeval_t now;
    uint32_t timer_id;
    uint32_t ret;

    expires.tval64 = expires_time;
    now.tval64 = timer_stamp_value_read();
    time_next_tick.tval64 = timer_value_sub(&expires, &now);

    /*
     * For RTC type timer:seconds is always integer
     * Because of instruction execute time, we should calibrate the seconds to interger and set nsec to zero
     */
    if (timer_class == TIMER_RTC) {
        hm_debug("timer is RTC, calibrate the seconds\n");
        time_next_tick.tval.sec += 1;
        time_next_tick.tval.nsec = 0;
        timer_id = TIMER_INDEX_RTC;
    } else {
        hm_debug("timer is timer60, do not to need calibrate the time\n");
        timer_id = TIMER_INDEX_TIMER;
    }

    hm_debug("sec = 0x%x nsec = 0x%x\n", time_next_tick.tval.sec, time_next_tick.tval.nsec);
    if ((time_next_tick.tval.sec < 0) ||
        ((time_next_tick.tval.sec == 0) &&
         (time_next_tick.tval.nsec < 0))) {
        clock_cycles = MIN_CLOCK_CYCLES;
        hm_error("the expire time is gone, excute the fiq handler at once %d: expires at %d.%d and now is %d.%d\n",
                 timer_class, expires.tval.sec, expires.tval.nsec, now.tval.sec, now.tval.nsec);
    } else {
        ret = timer_timeval_to_clock(&time_next_tick, timer_class, &clock_cycles);
        if (ret != TMR_DRV_SUCCESS) {
            hm_error("get clock cycles fail\n");
            clock_cycles = MIN_CLOCK_CYCLES;
        }
    }
    g_timer_cpu_info.expires_next[timer_id] = expires;

    timer_tick_trigger(clock_cycles, timer_class);
}

uint32_t timer_event_start(timer_event *timer_node, timeval_t *time, const struct tee_uuid *uuid)
{
    timeval_t temp_time;
    uint32_t timer_id = TIMER_INDEX_TIMER;

    if ((timer_node == NULL) || (time == NULL) || (uuid == NULL)) {
        hm_error("detect null pointer\n");
        return OS_ERRNO_TIMER_INPUT_PTR_NULL;
    }

    timer_node = timer_event_avail_get(timer_node);
    if (timer_node == NULL) {
        hm_error("time event is not available!\n");
        return OS_ERRNO_TIMER_EVENT_NOT_AVAILABLE;
    }

    if (memcmp(uuid, (&timer_node->timer_attr.uuid), sizeof(timer_node->timer_attr.uuid)) != 0) {
        hm_error("timer node is not belong to the uuid\n");
        return TMR_DRV_ERROR;
    }

    if (timer_node->state == TIMER_STATE_ACTIVE) {
        hm_error("timer event is already active\n");
        return OS_ERRNO_TIMER_EVENT_NOT_AVAILABLE;
    }

    if (timer_node->timer_class == TIMER_RTC)
        timer_id = TIMER_INDEX_RTC;

    if ((time->tval.nsec > (NS_PER_SECONDS - 1)) || (time->tval.nsec < 0) ||
        (time->tval.sec < 0) || (time->tval.sec == 0 && time->tval.nsec == 0))
        return OS_ERRNO_TIMER_INTERVAL_INVALID;

    temp_time.tval64 = timer_stamp_value_read();
    time->tval64 = timer_value_add(&temp_time, time);

    if (time->tval64 < 0)
        return OS_ERRNO_TIMER_INTERVAL_INVALID;

    hm_debug("Timer Event start time  sec = 0x%x nsec = 0x%x\n", time->tval.sec, time->tval.nsec);
    timer_expire_value_set(timer_node, time);

    if (timer_node->clk_info == NULL)
        return OS_ERRNO_TIMER_INTERVAL_INVALID;

    timer_event_queue_add(&timer_node->clk_info->active, timer_node);
#ifdef SOFT_RTC_TICK
    if (g_timer_cpu_info.expires_next[timer_id].tval64 > timer_node->expires.tval64) {
        if (g_timer_cpu_info.expires_next[TIMER_INDEX_TIMER - timer_id].tval64 > timer_node->expires.tval64)
            timer_tick_event(timer_node->expires.tval64, timer_node->timer_class);
        else
            g_timer_cpu_info.expires_next[timer_id].tval64 = timer_node->expires.tval64;
    }
#else
    if (g_timer_cpu_info.expires_next[timer_id].tval64 > timer_node->expires.tval64)
        timer_tick_event(timer_node->expires.tval64, timer_node->timer_class);
#endif

    return TMR_DRV_SUCCESS;
}

static void timer_event_handler_run(timer_event *timer_node)
{
    sw_timer_event_handler hndl = timer_node->handler;

    /* No need for spinlock as it is called from Interrupt context */
    timer_event_queue_del(timer_node);
    if (hndl != NULL)
        (void)hndl(timer_node);
}

static uint32_t timer_event_queue_register(timer_event *timer_node, timeval_t now)
{
    timeval_t add_one;
    timeval_t temp_time;

    if ((timer_node == NULL) || (timer_node->clk_info == NULL))
        return TMR_DRV_ERROR;

    if ((timer_node->timer_class == TIMER_GENERIC) || (timer_node->timer_class == TIMER_CLASSIC)) {
        add_one.tval.sec  = 0;
        add_one.tval.nsec = TIMER60_NS_THRD;
    } else if (timer_node->timer_class == TIMER_RTC) {
        add_one.tval.sec  = 1;
        add_one.tval.nsec = 0;
    } else {
        hm_error("invalid timerclass = 0x%x\n", timer_node->timer_class);
        return TMR_DRV_ERROR;
    }
    hm_debug("same timer event: need to do time add 1 seconds to avoid send IPI interrupt at the same time\n");
    temp_time.tval64 = timer_value_add(&now, &add_one);
    timer_event_queue_del(timer_node);
    timer_expire_value_set(timer_node, &temp_time);
    timer_event_queue_add(&timer_node->clk_info->active, timer_node);

    return TMR_DRV_SUCCESS;
}

static uint32_t timer_tick_event_run(const timer_event *timer_node, const timeval_t *now, uint32_t timer_id)
{
    timeval_t expires_next;
    timeval_t temp_time;
    timeval_t time_diff;

    (void)timer_id;
    temp_time.tval64 = timer_expire_value_get(timer_node, true);
    time_diff.tval64 = timer_value_sub(&temp_time, now);
    expires_next.tval64 = TIMEVAL_MAX;
    hm_debug("SW: current = 0x%x:0x%x and expires = 0x%x:0x%x and diff = 0x%x:0x%x\n",
             now->tval.sec, now->tval.nsec,
             temp_time.tval.sec, temp_time.tval.nsec,
             time_diff.tval.sec, time_diff.tval.nsec);

    /*
     * For RTC:if sec larger than 0:execute timer_tick_event
     * For Timer60:if nsec larger than 10000000, execute timer_tick_event
     */
    if ((time_diff.tval.sec > 0) || ((time_diff.tval.sec == 0) &&
        (time_diff.tval.nsec >= TIMER60_NS_THRD) && is_tick_timer(timer_node->timer_class))) {
        if (temp_time.tval64 < expires_next.tval64)
            expires_next = temp_time;

#ifdef SOFT_RTC_TICK
        if (expires_next.tval64 > g_timer_cpu_info.expires_next[TIMER_INDEX_TIMER - timer_id].tval64 &&
            g_timer_cpu_info.expires_next[TIMER_INDEX_TIMER - timer_id].tval64 > now->tval64) {
            g_timer_cpu_info.expires_next[timer_id] = expires_next;
            hm_debug("there is another tick need running\n");
            return TMR_DRV_SUCCESS;
        }
#endif
        timer_tick_event(expires_next.tval64, timer_node->timer_class);
        return TMR_DRV_SUCCESS;
    }

    return TMR_DRV_ERROR;
}

void timer_event_handler(uint32_t timer_id)
{
    struct timer_clock_info *clock_info = NULL;
    struct dlist_node *node = NULL;
    timer_event *timer_node = NULL;
    bool is_handler_run = false;
    uint32_t ret;
    timeval_t now;

    if ((timer_id != TIMER_INDEX_TIMER) && (timer_id != TIMER_INDEX_RTC)) {
        hm_error("timer interrupt: timer id is invalid!\n");
        return;
    }

    now.tval64 = timer_stamp_value_read();
    clock_info = &g_timer_cpu_info.clock_info[timer_id];

    while (1) {
        node = timer_event_queue_next(&clock_info->active);
        if (node == NULL)
            break;

        timer_node = dlist_entry(node, timer_event, node);
        if (timer_node == NULL)
            break;

        ret = timer_tick_event_run(timer_node, &now, timer_id);
        if (ret == TMR_DRV_SUCCESS)
            return;

        if (is_handler_run == false) {
            timer_node->state = TIMER_STATE_EXECUTING;
            timer_event_handler_run(timer_node);
            is_handler_run = true;
        } else {
            ret = timer_event_queue_register(timer_node, now);
            if (ret != TMR_DRV_SUCCESS)
                break;
        }
    }

    g_timer_cpu_info.expires_next[timer_id].tval64 = TIMEVAL_MAX;
    return;
}

#ifdef SOFT_RTC_TICK
static timer_event *find_next_node(const struct dlist_node *timer_node1,
                                   const struct dlist_node *timer_node2, uint32_t timer_id)
{
    timer_event *new_event1 = dlist_entry(timer_node1, timer_event, node);
    timer_event *new_event2 = dlist_entry(timer_node2, timer_event, node);

    if (dlist_empty(timer_node1)) {
        hm_error("new_event1 is null\n");
        g_timer_cpu_info.expires_next[timer_id].tval64 = TIMEVAL_MAX;
        return new_event2;
    }

    if (dlist_empty(timer_node2)) {
        hm_error("new_event2 is null\n");
        g_timer_cpu_info.expires_next[TIMER_INDEX_TIMER - timer_id].tval64 = TIMEVAL_MAX;
        return new_event1;
    }

    if (new_event1->expires.tval64 < new_event2->expires.tval64) {
        return new_event1;
    } else {
        g_timer_cpu_info.expires_next[timer_id].tval64 = new_event1->expires.tval64;
        return new_event2;
    }
}
#endif

static void timer_event_execute(const timer_event *timer_node, const struct timer_clock_info *clock_info)
{
    timer_event *next_event = NULL;
    bool have_another = true;
    uint32_t timer_id = (timer_node->timer_class == TIMER_RTC) ? TIMER_INDEX_RTC : TIMER_INDEX_TIMER;

#ifdef SOFT_RTC_TICK
    struct timer_clock_info *clock_info_temp = &g_timer_cpu_info.clock_info[TIMER_INDEX_TIMER - timer_id];
    if (timer_node->node.next == &clock_info->active && dlist_empty(&clock_info_temp->active)) {
        timer_disable(TICK_TIMER_BASE, TICK_TIMER_NUM);
        have_another = false;
    }
#else
    if (timer_node->node.next == &clock_info->active) {
        have_another = false;
        if (timer_node->timer_class != TIMER_RTC)
            timer_disable(TICK_TIMER_BASE, TICK_TIMER_NUM);
    }
#endif

    if (have_another == false) {
        hm_debug("timer event stop: there is no timer event exist\n");
        g_timer_cpu_info.expires_next[timer_id].tval64 = TIMEVAL_MAX;
        return;
    }

    hm_debug("timer event stop:there is another timer need to execute\n");
#ifdef SOFT_RTC_TICK
    if (timer_node->node.next == &clock_info->active) {
        g_timer_cpu_info.expires_next[timer_id].tval64 = TIMEVAL_MAX;
        next_event = dlist_entry(clock_info_temp->active.next, timer_event, node);
    } else if (dlist_empty(&clock_info_temp->active)) {
        g_timer_cpu_info.expires_next[TIMER_INDEX_TIMER - timer_id].tval64 = TIMEVAL_MAX;
        next_event = dlist_entry(timer_node->node.next, timer_event, node);
    } else {
        next_event = find_next_node(timer_node->node.next, clock_info_temp->active.next, timer_id);
    }
#else
    next_event = dlist_entry(timer_node->node.next, timer_event, node);
#endif
    timer_tick_event(next_event->expires.tval64, next_event->timer_class);
}

uint32_t timer_event_stop(timer_event *timer_node, const struct tee_uuid *uuid, bool real_event)
{
    struct timer_clock_info *clock_info = NULL;
    timeval_t expires;
    uint32_t timer_id = TIMER_INDEX_TIMER;

    if ((timer_node == NULL) || (uuid == NULL))
        return TMR_DRV_ERROR;

    if (!real_event) {
        timer_node = timer_event_avail_get(timer_node);
        if (timer_node == NULL) {
            hm_error("timer node is not available!\n");
            return TMR_DRV_ERROR;
        }
    }

    if (timer_node->state & TIMER_STATE_PENDING) {
        hm_error("the timer is waiting for call back, please stop it later!\n");
        return TMR_DRV_ERROR;
    }

    if (timer_node->state != TIMER_STATE_ACTIVE)
        return TMR_DRV_ERROR;

    if (memcmp(uuid, (&timer_node->timer_attr.uuid), sizeof(timer_node->timer_attr.uuid)) != 0) {
        hm_error("timer node is not belong to the uuid\n");
        return TMR_DRV_ERROR;
    }

    if (timer_node->timer_class == TIMER_RTC)
        timer_id = TIMER_INDEX_RTC;

    clock_info = &g_timer_cpu_info.clock_info[timer_id];
    if (&timer_node->node != timer_event_queue_next(&clock_info->active)) {
        timer_event_queue_del(timer_node);
        return TMR_DRV_SUCCESS;
    }

    expires.tval64 = timer_expire_value_get(timer_node, true);
    if (expires.tval64 != g_timer_cpu_info.expires_next[timer_id].tval64) {
        hm_debug("expire.tval64 is not equal to cpu info expires next\n");
        timer_event_queue_del(timer_node);
        return TMR_DRV_ERROR;
    }

    timer_event_execute(timer_node, clock_info);
    timer_event_queue_del(timer_node);

    return TMR_DRV_SUCCESS;
}

uint32_t timer_data_check_by_uuid(timer_notify_data_kernel *timer_data, const struct tee_uuid *uuid)
{
    struct timer_clock_info *clock_info = NULL;
    timer_event *timer_node = NULL;
    uint32_t timer_id = TIMER_INDEX_TIMER;

    if (uuid == NULL) {
        hm_error("uuid is invalid!\n");
        return TMR_DRV_ERROR;
    }

    if (timer_data == NULL) {
        hm_error("timer data is null!\n");
        return TMR_DRV_ERROR;
    }

    if (timer_data->property.timer_class == TIMER_RTC)
        timer_id = TIMER_INDEX_RTC;

    clock_info = &g_timer_cpu_info.clock_info[timer_id];

    dlist_for_each_entry(timer_node, &clock_info->active, timer_event, node) {
        if ((timer_node->timer_attr.type == timer_data->property.type) &&
            (memcmp(uuid, (&timer_node->timer_attr.uuid), sizeof(timer_node->timer_attr.uuid)) == 0)) {
            timer_data->property.handle = timer_node->handle;
            timer_data->expire_time = timer_node->timer_attr.expire_time;
            return TMR_DRV_SUCCESS;
        }
    }

    return TMR_DRV_ERROR;
}

struct timer_cpu_info *get_timer_cpu_info()
{
    return &g_timer_cpu_info;
}

static void recycle_timer_event(const TEE_UUID *uuid, const struct timer_clock_info *clock_info)
{
    timer_event *timer_node = NULL;
    timer_event *tmp_node = NULL;
    uint32_t ret;

    for (timer_node = dlist_first_entry(&clock_info->avail, timer_event, c_node);
         &(timer_node->c_node) != (&clock_info->avail);) {
        tmp_node = timer_node;
        timer_node = dlist_next_entry(timer_node, timer_event, c_node);

        if (memcmp(uuid, (&tmp_node->timer_attr.uuid), sizeof(tmp_node->timer_attr.uuid)) != 0)
            continue;

        if (tmp_node->timer_class != TIMER_CLASSIC && tmp_node->state != TIMER_STATE_INACTIVE)
            continue;
        if (tmp_node->state == TIMER_STATE_ACTIVE) {
            ret = timer_event_stop(tmp_node, uuid, true);
            if (ret != TMR_DRV_SUCCESS)
                hm_error("stop timer event failed\n");
        }
        ret = timer_event_destory_with_uuid(tmp_node, uuid, true);
        if (ret != TMR_DRV_SUCCESS)
            hm_error("destroy timer event failed\n");
    }
}

uint32_t release_timer_event_by_uuid(const TEE_UUID *uuid)
{
    struct timer_clock_info *clock_info = NULL;

    if (uuid == NULL) {
        hm_error("invalid uuid\n");
        return TMR_DRV_ERROR;
    }

    clock_info = &g_timer_cpu_info.clock_info[TIMER_INDEX_TIMER];
    recycle_timer_event(uuid, clock_info);
    clock_info = &g_timer_cpu_info.clock_info[TIMER_INDEX_RTC];
    recycle_timer_event(uuid, clock_info);

    return TMR_DRV_SUCCESS;
}
