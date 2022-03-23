/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee cipher osal lib
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "user_osal_lib.h"

/************************ Internal Structure Definition **********************/
/** \addtogroup      lib */
/** @{ */ /** <!-- [osal] */

/** @} */ /** <!-- ==== Structure Definition end ==== */

/** \addtogroup      osal lib */
hi_s32 queue_pool_create(queue_pool *queue, hi_u32 msg_size, hi_u32 depth)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(queue == HI_NULL);
    HI_LOG_CHECK_PARAM(msg_size == 0);
    HI_LOG_CHECK_PARAM(msg_size > QUEUE_POOL_MAX_MSG_SIZE);
    HI_LOG_CHECK_PARAM(depth > QUEUE_POOL_MAX_DEPTH);

    ret = pthread_mutex_init(&queue->mutex, HI_NULL);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(pthread_mutex_init, ret);
        return ret;
    }

    ret = pthread_cond_init(&queue->cond, HI_NULL);
    if (ret != HI_SUCCESS) {
        (hi_void)pthread_mutex_destroy(&queue->mutex);
        hi_err_print_call_fun_err(pthread_cond_init, ret);
        return ret;
    }

    queue->msg_data = crypto_calloc(msg_size, depth);
    if (queue->msg_data == HI_NULL) {
        (hi_void)pthread_mutex_destroy(&queue->mutex);
        (hi_void)pthread_cond_destroy(&queue->cond);
        hi_err_print_call_fun_err(calloc, HI_NULL);
        return HI_ERR_CIPHER_FAILED_MEM;
    }

    queue->depth = depth;
    queue->msg_size = msg_size;
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 queue_pool_destroy(queue_pool *queue)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(queue == HI_NULL);

    ret = pthread_mutex_destroy(&queue->mutex);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(pthread_mutex_destroy, ret);
        return ret;
    }

    ret = pthread_cond_destroy(&queue->cond);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(pthread_cond_destroy, ret);
        return ret;
    }

    crypto_free(queue->msg_data);
    queue->msg_data = HI_NULL;

    ret = memset_s(queue, sizeof(queue_pool), 0, sizeof(queue_pool));
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memset_s, ret);
        return ret;
    }

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 queue_pool_read(queue_pool *queue, hi_void *msg, hi_u32 msg_size)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(queue == HI_NULL);
    HI_LOG_CHECK_PARAM(msg == HI_NULL);
    HI_LOG_CHECK_PARAM(queue->msg_size != msg_size);

    ret = pthread_mutex_lock(&queue->mutex);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(pthread_mutex_lock, ret);
        return ret;
    }

    while (queue->count == 0) {
        ret = pthread_cond_wait(&queue->cond, &queue->mutex);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(pthread_cond_wait, ret);
            return ret;
        }
    }

    ret = memcpy_s(msg, msg_size, queue->msg_data + queue->tail * queue->msg_size, queue->msg_size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        return ret;
    }

    /* next */
    queue->count -= 1;
    queue->tail = (queue->tail + 1) % queue->depth;

    pthread_mutex_unlock(&queue->mutex);

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_s32 queue_pool_write(queue_pool *queue, const hi_void *msg, hi_u32 msg_size)
{
    hi_s32 ret;

    hi_dbg_func_enter();

    HI_LOG_CHECK_PARAM(queue == HI_NULL);
    HI_LOG_CHECK_PARAM(msg == HI_NULL);
    HI_LOG_CHECK_PARAM(queue->msg_size != msg_size);

    ret = pthread_mutex_lock(&queue->mutex);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(pthread_mutex_lock, ret);
        return ret;
    }

    /* wait queue non-full */
    while (queue->count == queue->depth) {
        pthread_mutex_unlock(&queue->mutex);
        TEE_Wait(1);
        ret = pthread_mutex_lock(&queue->mutex);
        if (ret != HI_SUCCESS) {
            hi_err_print_call_fun_err(pthread_mutex_lock, ret);
            return ret;
        }
    }

    ret = memcpy_s(queue->msg_data + queue->head * queue->msg_size, queue->msg_size, msg, msg_size);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(memcpy_s, ret);
        pthread_mutex_unlock(&queue->mutex);
        return ret;
    }

    /* next */
    queue->count += 1;
    queue->head = (queue->head + 1) % queue->depth;

    ret = pthread_cond_signal(&queue->cond);
    if (ret != HI_SUCCESS) {
        hi_err_print_call_fun_err(pthread_cond_signal, ret);
        pthread_mutex_unlock(&queue->mutex);
        return ret;
    }

    pthread_mutex_unlock(&queue->mutex);

    hi_dbg_func_exit();
    return HI_SUCCESS;
}

hi_void *crypto_calloc(hi_u32 element_num, hi_u32 element_size)
{
    hi_s32 ret;
    hi_void *ptr = HI_NULL;
    hi_u32 length;

    length = element_num * element_size;

    ptr = crypto_malloc(length);
    if (ptr == HI_NULL) {
        hi_err_print_call_fun_err(crypto_malloc, 0);
        return HI_NULL;
    }

    ret = memset_s(ptr, length, 0, length);
    if (ret != HI_SUCCESS) {
        crypto_free(ptr);
        hi_err_print_call_fun_err(memset_s, ret);
        return HI_NULL;
    }

    return ptr;
}

hi_s32 CRYPTO_IOCTL(hi_u32 cmd, const hi_void *argp)
{
    hi_u32 args[] = { cmd, (hi_u32)(uintptr_t)argp };

    return hm_drv_call(HI_TEE_SYSCALL_CIPHER, args, ARRAY_SIZE(args));
}

/** @} */ /** <!-- ==== API Code end ==== */
