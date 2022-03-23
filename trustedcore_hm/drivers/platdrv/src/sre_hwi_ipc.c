/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Safe time function setting
 * Create: 2020-02-04
 */
#include "sre_hwi_ipc.h"
#include <stdlib.h>
#include <dlist.h>
#include <errno.h>
#include <pthread.h>
#include <irqmgr.h>
#include <sre_typedef.h>
#include <sre_syscalls_id.h>
#include <sre_syscall.h>
#include <sre_access_control.h>
#include <msg_ops.h>
#include <tee_defines.h>
#include <tee_log.h>
#include "drv_module.h"
#include "drv_pal.h"
#include "hmdrv_stub.h" /* keep this last */
#include "drv_param_type.h"
#include "drv_thread.h"

#define OS_HWI_IPC_MESSAGE_BASE 0x0F10U
#define os_hwi_ipc_irq(x)       ((OS_HWI_IPC_MESSAGE_BASE << 16) | (x))
#define CALL_TA_DEFAULT_CMD 0
#define CH_ONE 1

struct task_hwi_info {
    uint32_t task_pid;
    uint32_t hwi_num;
    struct dlist_node list;
};

static pthread_mutex_t g_ipc_lock;
DLIST_HEAD(g_stactive_task_hwilist);

/*
 * CODEREVIEW CHECKLIST
 * CALLER: add_tp_list, tui_end_func, tui_end_func1
 * ARG: arg always valid
 * RET: error returns for ipc_msg_qsend processed
 */
void os_hwi_ipc_handler(uint32_t arg)
{
    struct task_hwi_info *task_node = NULL;
    uint32_t ret;
    int32_t result;

    result = pthread_mutex_lock(&g_ipc_lock);
    if (result != 0) {
        tloge("lock mutex error\n");
        return;
    }

    dlist_for_each_entry(task_node, &g_stactive_task_hwilist, struct task_hwi_info, list) {
        if (task_node->hwi_num == arg) {
            ret = ipc_msg_qsend(CALL_TA_DEFAULT_CMD, os_hwi_ipc_irq(task_node->hwi_num), task_node->task_pid, CH_ONE);
            if (ret != 0)
                tloge("tp_list ipc Msg Snd error\n");
        }
    }

    /*
     * Send a notification IRQ to unblock the NWD part, for long lasting IRQ
     * NWD might have already went to sleep
     */
    gic_spi_notify();

    result = pthread_mutex_unlock(&g_ipc_lock);
    if (result != 0)
        tloge("unlock mutex error\n");
}

/*
 * CODEREVIEW CHECKLIST
 * CALLER: sre_swi_handler
 * ARG: hwi_num: checked inside
 * RET: error return of malloc processed
 * LEAK: memory alloced will be free in hwi_msg_unregister
 */
uint32_t hwi_msg_register(uint32_t hwi_num)
{
    int32_t ret;
    struct task_hwi_info *task_node = NULL;
    pid_t caller_pid = INVALID_CALLER_PID;

    if (hwi_num >= (uint32_t)MAX_IRQ)
        return EINVAL;

    ret = pthread_mutex_lock(&g_ipc_lock);
    if (ret != 0) {
        tloge("register lock mutex error\n");
        return EPERM;
    }

    task_node = malloc(sizeof(*task_node));
    if (task_node == NULL) {
        ret = pthread_mutex_unlock(&g_ipc_lock);
        if (ret != 0) {
            tloge("register unlock mutex error\n");
            return EPERM;
        }
        return ENOMEM;
    }

    tid_t tid;
    ret = hm_gettid(&tid);
    if (ret != 0) {
        (void)pthread_mutex_unlock(&g_ipc_lock);
        free(task_node);
        hm_error("failed to get tid\n");
        return EINVAL;
    }
    ret = get_callerpid_by_tid(tid, &caller_pid);
    if (ret != DRV_CALL_OK) {
        (void)pthread_mutex_unlock(&g_ipc_lock);
        free(task_node);
        hm_error("get_callerpid_by_tid failed!\n");
        return EINVAL;
    }

    task_node->task_pid = (uint32_t)caller_pid;
    task_node->hwi_num  = hwi_num;
    dlist_insert_tail(&task_node->list, &g_stactive_task_hwilist);

    ret = pthread_mutex_unlock(&g_ipc_lock);
    if (ret != 0) {
        dlist_delete(&task_node->list);
        free(task_node);
        tloge("register unlock mutex error\n");
        return EPERM;
    }

    return 0;
}

/*
 * CODEREVIEW CHECKLIST
 * CALLER: sre_swi_handler
 * ARG: hwi_num: checked inside
 */
uint32_t hwi_msg_unregister(uint32_t hwi_num)
{
    int32_t ret;
    struct task_hwi_info *task_node = NULL;
    struct task_hwi_info *tmp = NULL;
    pid_t caller_pid = INVALID_CALLER_PID;

    if (hwi_num >= (uint32_t)MAX_IRQ)
        return EINVAL;

    ret = pthread_mutex_lock(&g_ipc_lock);
    if (ret != 0) {
        tloge("deregister lock mutex error\n");
        return EPERM;
    }

    tid_t tid;
    ret = hm_gettid(&tid);
    if (ret != 0) {
        hm_error("failed to get tid\n");
        (void)pthread_mutex_unlock(&g_ipc_lock);
        return EINVAL;
    }
    ret = get_callerpid_by_tid(tid, &caller_pid);
    if (ret != 0) {
        hm_error("failed to get caller pid\n");
        (void)pthread_mutex_unlock(&g_ipc_lock);
        return EINVAL;
    }

    dlist_for_each_entry_safe(task_node, tmp, &g_stactive_task_hwilist, struct task_hwi_info, list) {
        if (task_node->hwi_num == hwi_num && task_node->task_pid == (uint32_t)caller_pid) {
            dlist_delete(&task_node->list);
            free(task_node);
            if (pthread_mutex_unlock(&g_ipc_lock) != 0) {
                tloge("deregister unlock mutex error\n");
                return EPERM;
            }
            return 0;
        }
    }

    ret = pthread_mutex_unlock(&g_ipc_lock);
    if (ret != 0) {
        tloge("deregister unlock mutex error\n");
        return EPERM;
    }

    return EINVAL;
}

static int32_t hwi_register_syscall(int32_t swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret;

    if (params == NULL || params->args == 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_HWI_IPCREGISTER, permissions, HWIMSG_GROUP_PERMISSION)
        ret = hwi_msg_register((uint32_t)args[0]);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(SW_SYSCALL_HWI_IPCDEREGISTER, permissions, HWIMSG_GROUP_PERMISSION)
        ret = hwi_msg_unregister((uint32_t)args[0]);
        args[0] = ret;
        SYSCALL_END;
        default:
            return -1;
    }
    return 0;
}

DECLARE_TC_DRV(
        hwi_register_driver,
        0,
        0,
        0,
        TC_DRV_MODULE_INIT,
        NULL,
        NULL,
        hwi_register_syscall,
        NULL,
        NULL
);
