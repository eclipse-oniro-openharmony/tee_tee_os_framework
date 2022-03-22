/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: timer event related functions defined in this file.
 * Create: 2021-05-27
 */
#include "rtc_timer_event.h"
#include <securec.h>
#include <sys/usrsyscall_ext.h>
#include <sys/usrsyscall_new_ext.h>
#include <limits.h>
#include <procmgr_ext.h>
#include <msg_ops.h>
#include <hmlog.h>
#include "timer_sys.h"
#include "timer_init.h"
#include "timer_rtc.h"
#include "tee_mem_mgmt_api.h"
#include "timer_types.h"
#include "crypto_driver_adaptor.h"

#define GLOBAL_SERVICE_NAME "TEEGlobalTask"
#define TIMER60_NS_THRD     10000000
#define CPU_CORE_0 0
#define MAX_VALUE_SIGNED_32BIT 0x7FFFFFFF
#define MAX_RTC_TIMER_EVENT_NUM 32
#define MS_PER_SEC     1000
#define MAX_TIMES_GENERATE_SEED 2

static struct timer_cpu_info g_timer_cpu_info;
static uint32_t g_mix_seed;

uint32_t get_mix_seed(void)
{
    uint32_t count = 0;
    uint32_t seed;
    uint32_t ret;

    if (g_mix_seed != 0)
        return g_mix_seed;

    /* test MAX_TIMES_GENERATE_SEED times, in case of seed = 0 */
    while (count < MAX_TIMES_GENERATE_SEED) {
        count++;
        ret = hw_generate_random(&seed, sizeof(seed));
        if ((ret != TMR_DRV_SUCCESS) || (seed == 0))
            continue;

        g_mix_seed = seed;
        break;
    }

    return g_mix_seed;
}

void timer_cpu_info_init(void)
{
    g_timer_cpu_info.expires_next[TIMER_INDEX_RTC].tval64 = TIMEVAL_MAX;
    g_timer_cpu_info.clock_info[TIMER_INDEX_RTC].cpu_info = &g_timer_cpu_info;
    g_timer_cpu_info.clock_info[TIMER_INDEX_RTC].clock_id = TIMER_INDEX_RTC;
    dlist_init(&g_timer_cpu_info.clock_info[TIMER_INDEX_RTC].active);
    dlist_init(&g_timer_cpu_info.clock_info[TIMER_INDEX_RTC].avail);
}

int32_t check_timer_event_max_num(int32_t timer_class, const struct tee_uuid *uuid)
{
    uint32_t timer_event_num = 0;
    struct timer_clock_info *clock_info = NULL;
    timer_event *timer_node = NULL;

    clock_info = &g_timer_cpu_info.clock_info[TIMER_INDEX_RTC];
    dlist_for_each_entry(timer_node, &clock_info->avail, timer_event, c_node) {
        if (timer_node->timer_class == timer_class &&
            memcmp(uuid, (&timer_node->timer_attr.uuid), sizeof(timer_node->timer_attr.uuid)) == 0)
            timer_event_num++;
    }

    if (timer_event_num < MAX_RTC_TIMER_EVENT_NUM)
        return TMR_DRV_SUCCESS;

    return TMR_DRV_ERROR;
}

uint32_t timer_timeval_to_clock(const timeval_t *time, uint64_t *clock_cycles)
{
    if (time == NULL || clock_cycles == NULL) {
        hm_error("time params error\n");
        return TMR_DRV_ERROR;
    }

    if ((time->tval.sec < 0) || (time->tval.nsec < 0)) {
        hm_error("time params error, time->tval.sec = %d, time->tval.nsec = %d\n", time->tval.sec, time->tval.nsec);
        return TMR_DRV_ERROR;
    }

    *clock_cycles = time->tval.sec * TIMER_CLK_FREQ +  time->tval.nsec * (TIMER_CLK_FREQ / MS_PER_SEC);
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

static void timer_tick_event(int64_t expires_time)
{
    timeval_t time_next_tick;
    uint64_t clock_cycles;
    timeval_t expires;
    uint32_t cur_seconds;
    uint32_t ret;

    expires.tval64 = expires_time;
    cur_seconds = timer_rtc_value_get();
    if (expires.tval.sec > (int32_t)cur_seconds)
        time_next_tick.tval.sec = expires.tval.sec - cur_seconds;
    else
        time_next_tick.tval.sec = 1;
    time_next_tick.tval.nsec = 0;

    ret = timer_timeval_to_clock(&time_next_tick, &clock_cycles);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("get clock cycles fail\n");
        clock_cycles = MIN_CLOCK_CYCLES;
    }

    g_timer_cpu_info.expires_next[TIMER_INDEX_RTC] = expires;
    timer_tick_trigger(clock_cycles);
}

static timer_event *timer_event_avail_get(const timer_event *event)
{
    struct timer_clock_info *clock_info = NULL;
    timer_event *temp = NULL;

    clock_info = &g_timer_cpu_info.clock_info[TIMER_INDEX_RTC];
    dlist_for_each_entry(temp, &clock_info->avail, timer_event, c_node) {
        hm_debug("timer_event_avail_get temp %x, event %x\n", temp->handle, (uint32_t)event);
        if (temp->handle == (uint64_t)(uintptr_t)event)
            return temp;
    }

    return NULL;
}

int64_t timer_expire_value_get(const timer_event *timer_node, bool real_event)
{
    if (real_event == false)
        timer_node = timer_event_avail_get(timer_node);

    if (timer_node == NULL)
        return TIMEVAL_MAX;
    hm_debug("timer_expire_value_get expire %x s %x ns\n", timer_node->expires.tval.sec, timer_node->expires.tval.nsec);
    return timer_node->expires.tval64;
}

static uint32_t timer_tick_event_run(const timer_event *timer_node, const uint32_t *now, uint32_t timer_id)
{
    timeval_t expires_next;
    timeval_t temp_time;
    timeval_t time_diff;

    (void)timer_id;
    temp_time.tval64 = timer_expire_value_get(timer_node, true);
    time_diff.tval.sec = temp_time.tval.sec - (int32_t)*now;
    expires_next.tval64 = TIMEVAL_MAX;
    hm_debug("SW: current = 0x%x:0x%x and expires = 0x%x:0x%x and diff = 0x%x:0x%x\n",
             now->tval.sec, now->tval.nsec,
             temp_time.tval.sec, temp_time.tval.nsec,
             time_diff.tval.sec, time_diff.tval.nsec);

    /*
     * For RTC:if sec larger than 0:execute timer_tick_event
     * For Timer60:if nsec larger than 10000000, execute timer_tick_event
     */
    if (time_diff.tval.sec > 0) {
        if (temp_time.tval64 < expires_next.tval64)
            expires_next = temp_time;

        timer_tick_event(expires_next.tval64);
        return TMR_DRV_SUCCESS;
    }

    return TMR_DRV_ERROR;
}

static void timer_event_queue_del(timer_event *timer_node)
{
    dlist_delete(&timer_node->node);
    timer_node->state = TIMER_STATE_INACTIVE;
}

static void timer_event_handler_run(timer_event *timer_node)
{
    sw_timer_event_handler hndl = timer_node->handler;

    /* No need for spinlock as it is called from Interrupt context */
    timer_event_queue_del(timer_node);
    if (hndl != NULL)
        (void)hndl(timer_node);
}

static void timer_expire_value_set(timer_event *timer_node, const timeval_t *expire_value)
{
    timer_node->expires = *expire_value;
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

static uint32_t timer_event_queue_register(timer_event *timer_node, uint32_t now)
{
    timeval_t add_one;
    timeval_t temp_time;

    if ((timer_node == NULL) || (timer_node->clk_info == NULL))
        return TMR_DRV_ERROR;

    if (timer_node->timer_class == TIMER_RTC) {
        add_one.tval.sec  = 1;
        add_one.tval.nsec = 0;
    } else {
        hm_error("invalid timerclass = 0x%x\n", timer_node->timer_class);
        return TMR_DRV_ERROR;
    }
    hm_debug("same timer event: need to do time add 1 seconds to avoid send IPI interrupt at the same time\n");
    temp_time.tval.sec = now + add_one.tval.sec;
    timer_event_queue_del(timer_node);
    timer_expire_value_set(timer_node, &temp_time);
    timer_event_queue_add(&timer_node->clk_info->active, timer_node);

    return TMR_DRV_SUCCESS;
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

void timer_event_handler(uint32_t timer_id)
{
    struct timer_clock_info *clock_info = NULL;
    struct dlist_node *node = NULL;
    timer_event *timer_node = NULL;
    bool is_handler_run = false;
    uint32_t ret;
    uint32_t now;

    if (timer_id != TIMER_INDEX_RTC) {
        hm_error("timer interrupt: timer id is invalid!\n");
        return;
    }

    now = timer_rtc_value_get();
    clock_info = &g_timer_cpu_info.clock_info[timer_id];

    while (1) {
        node = timer_event_queue_next(&clock_info->active);
        if (node == NULL)
            break;

        timer_node = DLIST_ENTRY(node, timer_event, node);
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

static int32_t timer_event_init(const sw_timer_event_handler handler, int32_t timer_class, const void *priv_data,
                                timer_event *new_event, const struct tee_uuid *uuid)
{
    errno_t ret_s;
    uint32_t seed = get_mix_seed();

    (void)handler;

    new_event->clk_info = &g_timer_cpu_info.clock_info[TIMER_INDEX_RTC];
    dlist_init(&new_event->node);
    dlist_init(&new_event->c_node);

    new_event->expires.tval64 = TIMEVAL_MAX;
    new_event->state = TIMER_STATE_INACTIVE;
    new_event->callback_mode = TIMER_CALLBACK_HARDIRQ;
    new_event->timer_class = timer_class;
    new_event->handle = ((uint64_t)(uintptr_t)new_event) ^ seed;
    new_event->handler = timer_rtc_wait_handler;

    ret_s = memcpy_s(&(new_event->timer_attr), sizeof(new_event->timer_attr),
                     priv_data, sizeof(new_event->timer_attr));
    if (ret_s != EOK) {
        hm_error("timer event private data init: memcpy failed! ret_s is %d\n", ret_s);
        return TMR_DRV_ERROR;
    }

    ret_s = memcpy_s(&(new_event->timer_attr.uuid), sizeof(new_event->timer_attr.uuid),
                     uuid, sizeof(uuid));
    if (ret_s != EOK) {
        hm_error("memcpy failed! ret  is %d\n", ret_s);
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

timer_event *timer_event_create(const sw_timer_event_handler handler, int32_t timer_class,
                                const void *priv_data, const struct tee_uuid *uuid)
{
    timer_event *new_event = NULL;
    int32_t ret;

    if (timer_class != TIMER_RTC || priv_data == NULL) {
        hm_error("invalid param\n");
        return NULL;
    }

    ret = check_timer_event_max_num(timer_class, uuid);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("max timer event num limits\n");
        return NULL;
    }

    new_event = (timer_event *)TEE_Malloc(sizeof(*new_event), 0);
    if (new_event == NULL) {
        hm_error("Malloc failed in Creating New Timer event\n");
        return NULL;
    }

    ret = timer_event_init(handler, timer_class, priv_data, new_event, uuid);
    if (ret != 0) {
        hm_error("timer event init failed! ret is %d\n", ret);
        (void)TEE_Free(new_event);
        return NULL;
    }

    if (new_event->clk_info == NULL) {
        hm_error("new event clock info is NULL\n");
        (void)TEE_Free(new_event);
        return NULL;
    }
    dlist_insert_head(&new_event->c_node, &new_event->clk_info->avail);

    return (timer_event *)(uintptr_t)new_event->handle;
}

uint32_t timer_event_start(timer_event *timer_node, const timeval_t *time, const struct tee_uuid *uuid)
{
    uint32_t cur_seconds;
    timeval_t expire_time;

    if ((timer_node == NULL) || (time == NULL) || (uuid == NULL)) {
        hm_error("detect null pointer\n");
        return TMR_DRV_ERROR;
    }

    timer_node = timer_event_avail_get(timer_node);
    if (timer_node == NULL) {
        hm_error("time event is not available!\n");
        return TMR_DRV_ERROR;
    }

    if (memcmp(uuid, (&timer_node->timer_attr.uuid), sizeof(timer_node->timer_attr.uuid)) != 0) {
        hm_error("timer node is not belong to the uuid\n");
        return TMR_DRV_ERROR;
    }

    if (timer_node->state == TIMER_STATE_ACTIVE) {
        hm_error("timer event is already active\n");
        return TMR_DRV_ERROR;
    }

    if ((time->tval.nsec > (NS_PER_SECONDS - 1)) ||
        (time->tval.nsec < 0) ||
        ((uint32_t)(time->tval.sec) > MAX_VALUE_SIGNED_32BIT))
        return TMR_DRV_ERROR;

    cur_seconds = timer_rtc_value_get();
    if (time->tval.sec > (int32_t)(MAX_VALUE_SIGNED_32BIT - cur_seconds))
        return TMR_DRV_ERROR;

    expire_time.tval.sec = cur_seconds + time->tval.sec;
    expire_time.tval.nsec = 0;
    timer_expire_value_set(timer_node, &expire_time);

    if (timer_node->clk_info == NULL)
        return TMR_DRV_ERROR;

    timer_event_queue_add(&timer_node->clk_info->active, timer_node);

    if (g_timer_cpu_info.expires_next[TIMER_INDEX_RTC].tval64 > timer_node->expires.tval64)
        timer_tick_event(timer_node->expires.tval64);

    return TMR_DRV_SUCCESS;
}

static void timer_event_execute(const timer_event *timer_node, const struct timer_clock_info *clock_info)
{
    timer_event *next_event = NULL;

    if (timer_node->node.next == &clock_info->active) {
        hm_debug("timer event stop: there is no timer event exist\n");
        timer_disable();
        g_timer_cpu_info.expires_next[TIMER_INDEX_RTC].tval64 = TIMEVAL_MAX;
        return;
    }

    hm_debug("timer event stop:there is another timer need to execute\n");
    next_event = DLIST_ENTRY(timer_node->node.next, timer_event, node);
    timer_tick_event(next_event->expires.tval64);
}

uint32_t timer_event_stop(timer_event *timer_node, const struct tee_uuid *uuid, bool real_event)
{
    struct timer_clock_info *clock_info = NULL;
    timeval_t expires;

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

    clock_info = &g_timer_cpu_info.clock_info[TIMER_INDEX_RTC];
    if (&timer_node->node != timer_event_queue_next(&clock_info->active)) {
        timer_event_queue_del(timer_node);
        return TMR_DRV_SUCCESS;
    }

    expires.tval64 = timer_expire_value_get(timer_node, true);
    if (expires.tval64 != g_timer_cpu_info.expires_next[TIMER_INDEX_RTC].tval64) {
        hm_debug("expire.tval64 is not equal to cpu info expires next\n");
        timer_event_queue_del(timer_node);
        return TMR_DRV_ERROR;
    }

    timer_event_execute(timer_node, clock_info);
    timer_event_queue_del(timer_node);

    return TMR_DRV_SUCCESS;
}

uint32_t timer_event_destory_with_uuid(timer_event *timer_node, const struct tee_uuid *uuid, bool real_event)
{
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

    TEE_Free(timer_node);
    return TMR_DRV_SUCCESS;
}

int64_t timer_expire_get(const timer_event *timer_node)
{
    if (timer_node == NULL)
        return TIMEVAL_MAX;

    return timer_expire_value_get(timer_node, false);
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
