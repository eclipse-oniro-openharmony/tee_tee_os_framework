/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: DFX for klad
 * Author: Hisilicon hisecurity team
 * Create: 2019-08-07
 */

#include "drv_klad_timestamp.h"

#ifdef HI_KLAD_PERF_SUPPORT

static link_queue g_klad_queue;

link_queue *drv_klad_get_queue(hi_void)
{
    return &g_klad_queue;
}

hi_u32 klad_timestamp_queue_init(hi_void)
{
    link_queue *q = drv_klad_get_queue();

    mutex_init(&q->lock);
    q->length = 0;
    q->front = q->rear = hi_malloc(sizeof(queue_node));
    if (q->front == HI_NULL) {
        hi_err_klad("Memory allocate failed\n");
        return HI_FAILURE;
    }
    q->front->next = NULL;
    return HI_SUCCESS;
}

hi_u32 klad_timestamp_queue_destory(hi_void)
{
    link_queue *q = drv_klad_get_queue();

    mutex_lock(&q->lock);

    while (q->front != HI_NULL) {
        q->rear = q->front->next;
        hi_free(q->front);
        q->front = q->rear;
    }
    mutex_unlock(&q->lock);
    return HI_SUCCESS;
}

hi_u32 klad_timestamp_queue_clean(hi_void)
{
    link_queue *q = drv_klad_get_queue();

    queue_node *p = HI_NULL_PTR;
    queue_node *t = HI_NULL_PTR;
    mutex_lock(&q->lock);

    q->rear = q->front;
    p = q->front->next;
    q->front->next = NULL;
    while (p != HI_NULL) {
        t = p;
        p = p->next;
        hi_free(t);
    }
    q->length = 0;

    mutex_unlock(&q->lock);
    return HI_SUCCESS;
}

static hi_void __drv_klad_queue_set_value(queue_ptr p, hi_u32 klad_hw_id, hi_u32 klad_handle,
                                          struct klad_timestamp *timestamp)
{
    p->data.klad_hw_id = klad_hw_id;
    p->data.klad_handle = klad_handle;
    if (memcpy_s(&p->data.timestamp, sizeof(struct klad_timestamp),
                 timestamp, sizeof(*timestamp)) != EOK) {
        /* do nothing. */
        print_err_code(HI_ERR_KLAD_SEC_FAILED);
        return;
    }
    p->next = NULL;
}

hi_void klad_timestamp_queue(hi_u32 klad_hw_id, hi_u32 klad_handle, struct klad_r_base *base)
{
    link_queue *mq = drv_klad_get_queue();

    mutex_lock(&mq->lock);
    hi_dbg_klad("queue hw_id %d, handle 0x%x,  base %p\n", klad_hw_id, klad_handle, base);
    if (mq->length >= QUEUE_MAX_SIZE) {
        queue_ptr p = HI_NULL_PTR;
        if (mq->front == mq->rear) {
            goto out;
        }
        p = mq->front->next;
        mq->front->next = p->next;
        if (mq->rear == p) {
            mq->rear = mq->front;
        }
        __drv_klad_queue_set_value(p, klad_hw_id, klad_handle, &base->timestamp);

        mq->rear->next = p;
        mq->rear = p;
    } else {
        queue_ptr s = hi_malloc(sizeof(queue_node));
        if (s == HI_NULL) {
            hi_err_klad("memory allocate failed\n");
            goto out;
        }
        __drv_klad_queue_set_value(s, klad_hw_id, klad_handle, &base->timestamp);

        mq->rear->next = s;
        mq->rear = s;
        mq->length++;
    }
out:
    mutex_unlock(&mq->lock);

    return;
}
#else
hi_u32 klad_timestamp_queue_init(hi_void)
{
    return 0;
}
hi_u32 klad_timestamp_queue_destory(hi_void)
{
    return 0;
}
hi_u32 klad_timestamp_queue_clean(hi_void)
{
    return 0;
}

hi_void klad_timestamp_queue(hi_u32 klad_hw_id, hi_u32 klad_handle, struct klad_r_base *base)
{
    return 0;
}
#endif

