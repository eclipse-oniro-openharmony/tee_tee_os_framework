/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: message queue.
 * Author: Hisilicon security team
 * Create: 2019-08-12
 */

#include "tee_klad_msg_queue.h"
#include "tee_klad_type.h"

struct queue_pool {
    pthread_mutex_t mutex;
    sem_t  sem;
    hi_u32 msg_size;
    hi_u8 *msg_data;
    hi_u32 count;
    hi_u32 depth;
    hi_u32 head;
    hi_u32 tail;
};

static struct queue_pool g_queue_pool = {
    .msg_size = 0,
    .msg_data = HI_NULL,
    .count = 0,
    .depth = 0,
    .head = 0,
    .tail = 0,
};

struct queue_pool *__get_queue_pool(hi_void)
{
    return &g_queue_pool;
}

hi_s32 mq_create(hi_u32 msg_size, hi_u32 depth)
{
    hi_s32 ret;
    struct queue_pool *queue = __get_queue_pool();

    ret = mutex_init(&queue->mutex);
    if (ret != HI_SUCCESS) {
        print_err_func(mutex_init, ret);
        goto out;
    }

    ret = sem_init(&queue->sem, 0, 0);
    if (ret != HI_SUCCESS) {
        print_err_func(sem_init, ret);
        goto mutex_exit;
    }

    if (msg_size > QUEUE_POOL_MAX_MSG_SIZE || depth > QUEUE_POOL_MAX_DEPTH) {
        print_err_hex2(msg_size, depth);
        ret = HI_ERR_KLAD_INVALID_PARAM;
        goto sem_exit;
    }

    queue->msg_data = hi_malloc(msg_size * depth);
    if (queue->msg_data == HI_NULL) {
        print_err_hex2(msg_size, depth);
        ret = HI_ERR_KLAD_NO_MEMORY;
        goto sem_exit;
    }

    queue->depth = depth;
    queue->msg_size = msg_size;

    return HI_SUCCESS;
sem_exit:
    (hi_void)sem_destroy(&queue->sem);
mutex_exit:
    (hi_void)mutex_deinit(&queue->mutex);
out:
    return ret;
}

hi_s32 mq_destroy(hi_void)
{
    hi_s32 ret;
    struct queue_pool *queue = __get_queue_pool();

    ret = mutex_deinit(&queue->mutex);
    if (ret != HI_SUCCESS) {
        print_err_func(mutex_deinit, ret);
    }

    ret = sem_destroy(&queue->sem);
    if (ret != HI_SUCCESS) {
        print_err_func(sem_destroy, ret);
    }

    hi_free(queue->msg_data);
    queue->msg_data = HI_NULL;

    if (memset_s(queue, sizeof(struct queue_pool), 0, sizeof(*queue)) != EOK) {
        print_err_func(memset_s, HI_ERR_KLAD_SEC_FAILED);
        return HI_ERR_KLAD_SEC_FAILED;
    }

    return ret;
}

hi_s32 mq_resv(hi_void *msg, hi_u32 msg_size)
{
    hi_s32 ret;
    errno_t errno;
    struct queue_pool *queue = __get_queue_pool();

    if (queue == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    if (queue->msg_size != msg_size) {
        print_err_hex2(queue->msg_size, msg_size);
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    ret = sem_wait(&queue->sem);
    if (ret != HI_SUCCESS) {
        print_err_func(sem_wait, ret);
        goto out;
    }

    errno = memcpy_s(msg, msg_size, queue->msg_data + queue->tail * queue->msg_size, queue->msg_size);
    if (errno != EOK) {
        ret = HI_ERR_KLAD_SEC_FAILED;
        print_err_func(memcpy_s, ret);
        goto out;
    }

    /* next */
    queue->count -= 1;
    queue->tail = (queue->tail + 1) % queue->depth;
out:
    return ret;
}

hi_s32 mq_snd(const hi_void *msg, hi_u32 msg_size)
{
    hi_s32 ret = HI_ERR_KLAD_SEC_FAILED;
    errno_t errno;
    struct queue_pool *queue = __get_queue_pool();

    if (queue == HI_NULL) {
        print_err_code(HI_ERR_KLAD_NULL_PTR);
        return HI_ERR_KLAD_NULL_PTR;
    }

    if (queue->msg_size != msg_size) {
        print_err_hex2(queue->msg_size, msg_size);
        return HI_ERR_KLAD_INVALID_PARAM;
    }

    mutex_lock(&queue->mutex);

    errno = memcpy_s(queue->msg_data + queue->head * queue->msg_size, queue->msg_size, msg, msg_size);
    if (errno != EOK) {
        print_err_func(memcpy_s, ret);
        goto out;
    }

    /* next */
    queue->count += 1;
    queue->head = (queue->head + 1) % queue->depth;

    ret = sem_post(&queue->sem);
    if (ret != HI_SUCCESS) {
        print_err_func(sem_post, ret);
        goto out;
    }

out:
    mutex_unlock(&queue->mutex);
    return ret;
}

