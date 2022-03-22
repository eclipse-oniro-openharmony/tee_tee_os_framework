/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: Provides abstract thread interfaces for seplat.
 * Create: 2020/12/05
 */
#ifndef HAL_THREAD_H
#define HAL_THREAD_H

#define SEPLAT_HAL_LOCK_MAX_NUM 10

enum seplat_thread_err {
    SEPLAT_THREAD_INIT_NULL            = 0x1,
    SEPLAT_THREAD_LOCK_NOT_ENOUGH      = 0x2,
    SEPLAT_THREAD_LOCK_CREAT_FAIL      = 0x3,
    SEPLAT_THREAD_FREE_NULL            = 0x4,
};

typedef int hal_lock_t;

int hal_lock_init(hal_lock_t *lock);
void hal_lock(hal_lock_t *lock);
void hal_unlock(hal_lock_t *lock);

#endif
