/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Define the function related recycle callback.
 * Create: 2020-02-04
 */
#include "sre_dev_relcb.h"
#include <malloc.h>
#include <dlist.h>
#include <sre_task.h>
#include <sre_syscalls_id_ext.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <hmdrv_stub.h>
#include <tee_log.h>
#include <securec.h>
#include "drv_module.h"
#include "drv_pal.h"
#include "drv_param_type.h"
#include "drv_thread.h"

struct dev_relcb_task_st {
    uint32_t task_pid;
    struct dlist_node dev_relcb_list;
    struct dlist_node list;
};

struct dev_relcb_st {
    dev_release_callback dev_relcb;
    void *data;
    struct dlist_node list;
};

dlist_head(g_devrelcblist);
pthread_mutex_t g_dev_relcb_mutex = PTHREAD_MUTEX_INITIALIZER;
#ifdef FEATURE_SE
static uint64_t g_se_flag;

int se_release_cb(const void *data)
{
    (void)data;
    g_se_flag = 0;
    return 0;
}
#endif

/*
 * CODEREVIEW CHECKLIST
 * CALLER: task_register_devrelcb, task_unregister_devrelcb, os_task_exit
 * ARG: task_pid: checked by caller
 */
static struct dev_relcb_task_st *get_dev_relcb_task(uint32_t task_pid)
{
    struct dev_relcb_task_st *ptask = NULL;
    struct dev_relcb_task_st *tmp = NULL;

    dlist_for_each_entry_safe(ptask, tmp, &g_devrelcblist, struct dev_relcb_task_st, list) {
        if (ptask->task_pid == task_pid)
            return ptask;
    }

    return NULL;
}

/*
 * CODEREVIEW CHECKLIST
 * CALLER: scard_connect, sion_pool_flag_set, sre_swi_handler
 *            init_tui_sdriver, handle_unusual_SecureContentMem_RelCb,
 *            handle_SecureContentMem_RelCb
 * ARG: dev_relcb: checked inside
 *        data: any in valid(all caller input NULL)
 * LOG: prunningtask initialized
 *        devrelcb_entry initialized
 *        cb_use initialized
 *        pos    initialized
 *        tmp initialized
 * LEAK: never, all error paths for memory from malloc freed
 */
uint32_t task_register_devrelcb(dev_release_callback dev_relcb, void *data)
{
    uint32_t task_pid;
    struct dev_relcb_st *cb_use = NULL;
    struct dev_relcb_st *tmp = NULL;

    /* function must not be NULL */
    if (dev_relcb == NULL)
        return (uint32_t)OS_ERRNO_TSK_PTR_NULL;

    if (task_caller(&task_pid) != 0)
        return (uint32_t)OS_ERRNO_TSK_ID_INVALID;

    if (pthread_mutex_lock(&g_dev_relcb_mutex) != SRE_OK) {
        tloge("get lock failed in register devrelcb\n");
        return OS_ERROR;
    }

    struct dev_relcb_task_st *running_task = get_dev_relcb_task(task_pid);
    if (running_task == NULL) {
        running_task = malloc(sizeof(*running_task));
        if (running_task == NULL) {
            (void)pthread_mutex_unlock(&g_dev_relcb_mutex);
            return (uint32_t)OS_ERRNO_TSK_NO_MEMORY;
        }
        if (memset_s(running_task, sizeof(*running_task), 0, sizeof(*running_task)) != EOK) {
            free(running_task);
            (void)pthread_mutex_unlock(&g_dev_relcb_mutex);
            return (uint32_t)OS_ERRNO_TSK_NO_MEMORY;
        }
        running_task->task_pid = task_pid;
        dlist_init(&running_task->dev_relcb_list);
        dlist_insert_tail(&running_task->list, &g_devrelcblist);
    }

    (void)pthread_mutex_unlock(&g_dev_relcb_mutex);

    dlist_for_each_entry_safe(cb_use, tmp, &running_task->dev_relcb_list, struct dev_relcb_st, list) {
        if ((cb_use->dev_relcb == dev_relcb) && (data == cb_use->data)) {
            tloge("Found DevRelCb and its data, no need to register\n");
            return OS_ERRNO_TSK_HOOK_IS_FULL;
        }
    }

    struct dev_relcb_st *devrelcb_entry = malloc(sizeof(*devrelcb_entry));
    if (devrelcb_entry == NULL) {
        tloge("mem alloc error\n");
        return OS_ERRNO_TSK_NO_MEMORY;
    }

    devrelcb_entry->dev_relcb = dev_relcb;
    devrelcb_entry->data = data;
    dlist_insert_tail(&devrelcb_entry->list, &running_task->dev_relcb_list);

    return SRE_OK;
}

/*
 * CODEREVIEW CHECKLIST
 * CALLER: scard_disconnect, sion_pool_flag_unset,
 *         sre_swi_handler, init_tui_sdriver, handle_SecureContentMem_RelCb,
 *         handle_unusual_SecureContentMem_RelCb
 * ARG: dev_relcb: checked inside
 *      data: any in valid(all caller input NULL)
 * RET: error return of task_caller processed
 *      NULL return of get_dev_relcb_task processed
 */
void task_unregister_devrelcb(dev_release_callback dev_relcb, const void *data)
{
    uint32_t task_pid;
    struct dev_relcb_task_st *running_task = NULL;
    struct dev_relcb_st *cb_use = NULL;
    struct dev_relcb_st *tmp = NULL;

    if (dev_relcb == NULL)
        return;

    if (task_caller(&task_pid) != 0)
        return;

    if (pthread_mutex_lock(&g_dev_relcb_mutex) != SRE_OK) {
        tloge("get lock failed in unregister devrelcb\n");
        return;
    }

    running_task = get_dev_relcb_task(task_pid);
    if (running_task == NULL) {
        (void)pthread_mutex_unlock(&g_dev_relcb_mutex);
        return;
    }

    (void)pthread_mutex_unlock(&g_dev_relcb_mutex);

    dlist_for_each_entry_safe(cb_use, tmp, &running_task->dev_relcb_list, struct dev_relcb_st, list) {
        if ((cb_use->dev_relcb == dev_relcb) && (data == cb_use->data)) {
            dlist_delete(&cb_use->list);
            free(cb_use);
            return;
        }
    }

    tlogw("unregister dev_relcb failed!\n");
}

/* Keep this function for compatibility */
uint32_t SRE_TaskRegister_DevRelCb(dev_release_callback dev_relcb, void *data)
{
    return task_register_devrelcb(dev_relcb, data);
}

/* Keep this function for compatibility */
void SRE_TaskUnRegister_DevRelCb(dev_release_callback dev_relcb, const void *data)
{
    task_unregister_devrelcb(dev_relcb, data);
}

/*
 * CODEREVIEW CHECKLIST
 * CALLER: sre_swi_handler
 * ARG: task_pid: always valid
 * RET: NULL return of get_dev_relcb_task processed
 */
static void os_task_exit(uint32_t task_pid)
{
    pid_t orig_caller_pid = INVALID_CALLER_PID;
    struct dev_relcb_st *devrelcb_entry = NULL;
    struct dev_relcb_st *tmp = NULL;

    tid_t tid;
    int32_t ret = hm_gettid(&tid);
    if (ret != 0) {
        hm_error("failed to get tid\n");
        return;
    }
    ret = get_callerpid_by_tid(tid, &orig_caller_pid);
    if (ret != DRV_CALL_OK) {
        hm_error("get_callerpid_by_tid failed!\n");
        return;
    }

    if (pthread_mutex_lock(&g_dev_relcb_mutex) != SRE_OK) {
        tloge("get lock failed in unregister devrelcb\n");
        return;
    }

    struct dev_relcb_task_st *task = get_dev_relcb_task(task_pid);
    if (task == NULL) {
        (void)pthread_mutex_unlock(&g_dev_relcb_mutex);
        return;
    }

    dlist_delete(&task->list);
    (void)pthread_mutex_unlock(&g_dev_relcb_mutex);
    update_callerpid_by_tid(tid, task_pid);

    dlist_for_each_entry_safe(devrelcb_entry, tmp, &task->dev_relcb_list, struct dev_relcb_st, list) {
        dlist_delete(&devrelcb_entry->list);
        devrelcb_entry->dev_relcb(devrelcb_entry->data);
        free(devrelcb_entry);
    }

    update_callerpid_by_tid(tid, orig_caller_pid);

    free(task);
}

int32_t task_exit_syscall(int32_t swi_id, struct drv_param *params, uint64_t permissions)
{
    if (params == NULL || params->args == 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
    SYSCALL_PERMISSION(SW_SYSCALL_SYS_OSTSKEXIT, permissions, TASK_GROUP_PERMISSION)
    os_task_exit((uint32_t)args[0]);
    args[0] = 0;
    SYSCALL_END;

#ifdef FEATURE_SE
    uint32_t ret;
    SYSCALL_PERMISSION(SW_SYSCALL_SE_SETFLAG, permissions, SE_GROUP_PERMISSION)
    g_se_flag = args[0];
    if (g_se_flag == 1) {
        ret = task_register_devrelcb((dev_release_callback)se_release_cb, NULL);
        if (ret != SRE_OK) {
            tlogw("unregister dev_relcb failed\n");
            args[0] = ret;
        }
    } else {
        task_unregister_devrelcb((dev_release_callback)se_release_cb, NULL);
    }
    SYSCALL_END;

    SYSCALL_PERMISSION(SW_SYSCALL_SE_GETFLAG, permissions, SE_GROUP_PERMISSION)
    args[0] = g_se_flag;
    SYSCALL_END;
#endif

    default:
        return -1;
    }

    return 0;
}

DECLARE_TC_DRV(
    task_exit_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    task_exit_syscall,
    NULL,
    NULL
);

