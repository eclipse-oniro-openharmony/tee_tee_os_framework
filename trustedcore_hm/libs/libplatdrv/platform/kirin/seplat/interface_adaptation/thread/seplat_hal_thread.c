/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: Provides abstract thread interfaces for seplat.
 * Create: 2020/12/05
 */

#include "seplat_hal_thread.h"
#include "seplat_hal_log.h"
#include "types.h"
#include "pthread.h"
#include "seplat_errno.h"
#include "sre_typedef.h"

#define SEPLAT_THIS_MODULE SEPLAT_MODULE_HAL_THREAD
#define INVALID_LOCK (-1)

struct hal_lock_map {
    hal_lock_t *lock;
    pthread_mutex_t tee_lock;
};

struct hal_lock_map g_hal_lock_map[SEPLAT_HAL_LOCK_MAX_NUM] = { { 0 } };

int32_t hal_lock_init(hal_lock_t *lock)
{
    int32_t i;
    int32_t ret;

    if (!lock)
        return SEPLAT_ERRCODE(SEPLAT_THREAD_INIT_NULL);

    if (*lock < SEPLAT_HAL_LOCK_MAX_NUM && g_hal_lock_map[*lock].lock == lock)
        return SEPLAT_OK;

    for (i = 0; i < SEPLAT_HAL_LOCK_MAX_NUM; i++) {
        if (!g_hal_lock_map[i].lock)
            break;
    }
    if (i >= SEPLAT_HAL_LOCK_MAX_NUM)
        return SEPLAT_ERRCODE(SEPLAT_THREAD_LOCK_NOT_ENOUGH);

    *lock = i;
    g_hal_lock_map[*lock].lock = lock;

    ret = pthread_mutex_init(&g_hal_lock_map[*lock].tee_lock, NULL);
    if (ret != SRE_OK)
        return SEPLAT_ERRCODE(SEPLAT_THREAD_LOCK_CREAT_FAIL);

    return SEPLAT_OK;
}

void hal_lock(hal_lock_t *lock)
{
    if (!lock || *lock >= SEPLAT_HAL_LOCK_MAX_NUM || g_hal_lock_map[*lock].lock != lock)
        return;
    (void)pthread_mutex_lock(&g_hal_lock_map[*lock].tee_lock);
}

void hal_unlock(hal_lock_t *lock)
{
    if (!lock || *lock >= SEPLAT_HAL_LOCK_MAX_NUM || g_hal_lock_map[*lock].lock != lock)
        return;
    (void)pthread_mutex_unlock(&g_hal_lock_map[*lock].tee_lock);
}

void hal_lock_free(hal_lock_t *lock)
{
    if (!lock)
        return;

    if (*lock >= SEPLAT_HAL_LOCK_MAX_NUM || g_hal_lock_map[*lock].lock != lock)
        return;

    if (pthread_mutex_destroy(&g_hal_lock_map[*lock].tee_lock) != SRE_OK) {
        hal_print_error("seplat_dl: destroy lock fail %d\n", *lock);
        return;
    }

    g_hal_lock_map[*lock].lock = NULL;
    *lock = INVALID_LOCK;
}
