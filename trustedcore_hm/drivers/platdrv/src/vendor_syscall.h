/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: platdrv vendor cmd handle, adapt for mtk mdrv_open/mdrv_ioctl/mdrv_close
 * Create: 2020-10-12
 */
#ifndef PLATDRV_VENDOR_SYSCALL_H
#define PLATDRV_VENDOR_SYSCALL_H
#include <stdbool.h>
#include <pthread.h>
#include "sys/hm_types.h"
#include "drv_module.h"

struct module_control {
    pthread_mutex_t mtx;
    const struct syscall_entry *fn;
    uint32_t call_pid;
    bool open_flag; /* one module cannot be opened by two thread */
};

int32_t get_callerpid_and_job_handler(pid_t *call_pid, uint64_t *job_handler);
int32_t robust_mutex_init(pthread_mutex_t *mtx);
int32_t module_control_init(void);
int32_t get_lock_time(uint32_t timeout_ms, struct timespec *timeout);
int32_t drv_call_back_close_func(void *data);
#endif
