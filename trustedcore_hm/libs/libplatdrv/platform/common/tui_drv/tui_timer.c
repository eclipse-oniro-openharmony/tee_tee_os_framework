/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: timer implementation for tui driver
 * Author: DuJie dujie7@huawei.com
 * Create: 2020-04-22
 */
#include "tui_timer.h"

#include <libhwsecurec/securec.h>
#include <list.h>
#include <msg_ops.h>
#include <sre_hwi.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <timer.h>

struct timer_node {
    enum tui_drv_msg msg_id;
    timeval_t interval;
    int32_t caller_pid;
    timer_event *handle;
    struct list_head list_node;
};

static bool g_timer_enabled = false;
struct list_head g_timer_head;
static bool get_timer_enabled(void)
{
    bool tmp = g_timer_enabled;

    return tmp;
}

void set_timer_enabled(bool enabled)
{
    g_timer_enabled = enabled;
}

static void timer_node_free(struct timer_node *data)
{
    if (data->handle != NULL) {
        SRE_TimerEventStop(data->handle);
        uint32_t ret = SRE_TimerEventDestroy(data->handle);
        if (ret != 0)
            tloge("destroy tui timer 0x%x error ret=0x%x\n", data->msg_id, ret);

        data->handle = NULL;
    }

    TEE_Free(data);
}

static int32_t tui_timer_handler(void *data)
{
    struct timer_node *node = data;
    if (node == NULL || !get_timer_enabled())
        return -1;

    int32_t ret = ipc_msg_snd(node->msg_id, node->caller_pid, NULL, 0);
    if (ret != 0) {
        tloge("msg snd 0x%x to 0x%x error 0x%x\n", node->msg_id, node->caller_pid, ret);
        return -1;
    }

    return 0;
}

int32_t timer_node_create(timeval_t interval, enum tui_drv_msg msg_id, int32_t caller_pid)
{
    timeval_t val;
    int32_t ret;
    struct timer_node *node = TEE_Malloc(sizeof(*node), 0);
    if (node == NULL) {
        tloge("malloc failed size 0x%x for tui timer", sizeof(*node));
        return -1;
    }
    node->msg_id     = msg_id;
    node->interval   = interval;
    node->caller_pid = caller_pid;
    node->handle     = SRE_TimerEventCreate(tui_timer_handler, TIMER_CLASSIC, node);
    if (node->handle == NULL) {
        tloge("create tui timer error \n");
        TEE_Free(node);
        return -1;
    }

    val = node->interval;
    ret = SRE_TimerEventStart(node->handle, &val);
    if (ret != 0) {
        tloge("start tui timer error ret=0x%x\n", ret);
        (void)SRE_TimerEventDestroy(node->handle);
        TEE_Free(node);
        return -1;
    }

    list_add_tail(&node->list_node, &g_timer_head);

    return 0;
}

void timer_node_destroy(enum tui_drv_msg msg_id)
{
    struct timer_node *child = NULL;
    struct list_head *pos    = NULL;
    struct list_head *tmp    = NULL;
    list_for_each_safe(pos, tmp, &g_timer_head) {
        child = list_entry(pos, struct timer_node, list_node);
        if (child->msg_id == msg_id) {
            list_del(&child->list_node);
            timer_node_free(child);
            break;
        }
    }
}

void timer_node_start(enum tui_drv_msg msg_id)
{
    struct timer_node *child = NULL;
    struct list_head *pos    = NULL;
    struct list_head *tmp    = NULL;
    list_for_each_safe(pos, tmp, &g_timer_head) {
        child = list_entry(pos, struct timer_node, list_node);
        if (child->msg_id == msg_id) {
            timeval_t val = child->interval;
            (void)SRE_TimerEventStart(child->handle, &val);
            break;
        }
    }
}

void timer_node_stop(enum tui_drv_msg msg_id)
{
    struct timer_node *child = NULL;
    struct list_head *pos    = NULL;
    struct list_head *tmp    = NULL;
    list_for_each_safe(pos, tmp, &g_timer_head) {
        child = list_entry(pos, struct timer_node, list_node);
        if (child->msg_id == msg_id) {
            (void)SRE_TimerEventStop(child->handle);
            break;
        }
    }
}

static bool g_timer_init = false;
void tui_timer_init(void)
{
    if (g_timer_init)
        tui_timer_release();

#ifndef TEE_SUPPORT_TUI_MTK_DRIVER
    INIT_LIST_HEAD(&g_timer_head);
#else
    init_list_head(&g_timer_head);
#endif

    g_timer_init = true;
}

void tui_timer_release(void)
{
    if (!g_timer_init)
        return;

    /* stop and destroy all timer */
    set_timer_enabled(false);

    struct timer_node *child = NULL;
    struct list_head *pos    = NULL;
    struct list_head *tmp    = NULL;
    list_for_each_safe(pos, tmp, &g_timer_head) {
        child = list_entry(pos, struct timer_node, list_node);
        list_del(&child->list_node);
        timer_node_free(child);
        child = NULL;
    }

    g_timer_init = false;
}
