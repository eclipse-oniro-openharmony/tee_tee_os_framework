/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: define driver shared memory api
 * Create: 2022-01
 */

#include "drv_param_ops.h"
#include <stdio.h>
#include <drv_thread.h>
#include <hmlog.h>
#include <tee_sharemem_ops.h>

static int32_t get_drv_caller_taskid(uint32_t *taskid)
{
    tid_t tid;
    pid_t caller_pid;

    int32_t ret = hm_gettid(&tid);
    if (ret != 0) {
        hm_error("get tid failed\n");
        return -1;
    }

    ret = get_callerpid_by_tid(tid, &caller_pid);
    if (ret != 0) {
        hm_error("get tid:0x%x caller pid failed\n", tid);
        return -1;
    }

    *taskid = (uint32_t)caller_pid;
    return 0;
}

int32_t copy_from_client(uint64_t src, uint32_t src_size, uintptr_t dst, uint32_t dst_size)
{
    uint32_t taskid;
    int32_t ret = get_drv_caller_taskid(&taskid);
    if (ret != 0)
        return -1;

    /* Parameters are checked in copy_from_sharemem */
    ret = copy_from_sharemem(taskid, src, src_size, dst, dst_size);
    if (ret != 0) {
        hm_error("copy from task:0x%x failed\n", taskid);
        return -1;
    }

    return 0;
}

int32_t copy_to_client(uintptr_t src, uint32_t src_size, uint64_t dst, uint32_t dst_size)
{
    uint32_t taskid;
    int32_t ret = get_drv_caller_taskid(&taskid);
    if (ret != 0)
        return -1;

    /* Parameters are checked in copy_to_sharemem */
    ret = copy_to_sharemem(src, src_size, taskid, dst, dst_size);
    if (ret != 0) {
        hm_error("copy to task:0x%x failed\n", taskid);
        return -1;
    }

    return 0;
}
