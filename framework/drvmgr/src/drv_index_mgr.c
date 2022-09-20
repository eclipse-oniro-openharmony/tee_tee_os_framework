/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: define driver index function
 * Create: 2021-07-19
 */
#include "drv_index_mgr.h"
#include <pthread.h>
#include <tee_log.h>
#include <tee_bitmap.h>
#include "drv_fd_ops.h"

static uint8_t g_drv_index_bitmap[(DRV_INDEX_MAX) >> MOVE_BIT];
static pthread_mutex_t g_drv_index_mtx = PTHREAD_ROBUST_MUTEX_INITIALIZER;

int32_t alloc_drv_index(void)
{
    int32_t ret = drv_robust_mutex_lock(&g_drv_index_mtx);
    if (ret != 0) {
        tloge("get drv index mtx failed\n");
        return -1;
    }

    int32_t drv_index = get_valid_bit(g_drv_index_bitmap, DRV_INDEX_MAX);
    if (drv_index == -1) {
        tloge("cannot get drv index bit\n");
        ret = pthread_mutex_unlock(&g_drv_index_mtx);
        if (ret != 0)
            tloge("something wrong, unlock mtx in drv index failed 0x%x\n", ret);
        return -1;
    }

    set_bitmap(g_drv_index_bitmap, DRV_INDEX_MAX, drv_index);

    ret = pthread_mutex_unlock(&g_drv_index_mtx);
    if (ret != 0)
        tloge("something wrong, unlock mtx in drv index failed 0x%x\n", ret);

    return (drv_index + 1);
}

void clear_drv_index(int32_t drv_index)
{
    if (drv_index <= 0 || drv_index > DRV_INDEX_MAX) {
        tloge("invalid drv_index:0x%x\n", drv_index);
        return;
    }

    int32_t ret = drv_robust_mutex_lock(&g_drv_index_mtx);
    if (ret != 0) {
        tloge("get drv index mtx failed\n");
        return;
    }

    clear_bitmap(g_drv_index_bitmap, DRV_INDEX_MAX, (drv_index - 1));

    ret = pthread_mutex_unlock(&g_drv_index_mtx);
    if (ret != 0)
        tloge("something wrong, unlock mtx in drv index failed 0x%x\n", ret);
}
