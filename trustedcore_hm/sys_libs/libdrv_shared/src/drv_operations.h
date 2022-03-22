/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: declare drv fd manager function
 * Create: 2021-03-01
 */
#ifndef TEE_DRV_SERVER_SRC_DRV_FD_MANAGER_H
#define TEE_DRV_SERVER_SRC_DRV_FD_MANAGER_H

#include <list.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/hm_types.h>
#include "tee_driver_module.h"
#include "drv_dispatch.h"

#define TASK_FD_COUNT_MAX 32U

#define CALLER_TASKID_INDEX 4

struct fd_data {
    struct list_head data_list;
    uint64_t cmd_perm;
    pthread_mutex_t ref_mtx;
    pthread_cond_t ref_cond;
    uint32_t ref_cnt; /* locked by ref_mtx */
    struct drv_data drv;
};

struct drv_task {
    struct list_head task_list;
    uint32_t task_pid;
    uint32_t task_count; /* locked by task_mtx */
    struct list_head data_head; /* fd_data list head */
    pthread_mutex_t task_mtx;
    uint32_t ref_cnt; /* locked by g_drv_mtx */
};

int64_t driver_open(const struct tee_drv_param *params, const struct tee_driver_module *drv_func);
int64_t driver_ioctl(uint64_t fd, struct tee_drv_param *params,
    const struct tee_driver_module *drv_func, int64_t *fn_ret);
int64_t driver_close(uint64_t fd, const struct tee_drv_param *params);
int32_t driver_close_by_pid(uint32_t pid);
void driver_dump(void);
int32_t drv_robust_mutex_lock(pthread_mutex_t *mtx);
int32_t driver_register_cmd_perm(const struct tee_drv_param *params, int64_t *ret_val);
#endif
