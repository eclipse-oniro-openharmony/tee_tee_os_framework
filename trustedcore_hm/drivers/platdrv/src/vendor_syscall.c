/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: platdrv vendor cmd handle, adapt for mtk mdrv_open/mdrv_ioctl/mdrv_close
 * Create: 2020-10-12
 */
#include "vendor_syscall.h"
#include <sre_access_control.h>
#include <hmlog.h>
#include "api/errno.h"
#include "sys_timer.h"
#include "drv_call.h"
#include "sre_dev_relcb.h"
#include "drv_thread.h"
#include "hmdrv_stub.h"

#define DRV_MODULE_ID_INDEX 0
#define DRV_OPEN_PARAM_INDEX 1
#define DRV_INVOKE_CMD_INDEX 1
#define DRV_INVOKE_CMD_PARAM_INDEX 2
#define DRV_MODULE_MAX_ID ((MDRV_MODULE_ID_15) - (MDRV_MODULE_ID_0) + 1)

struct module_control g_module_control[DRV_MODULE_MAX_ID];

int32_t robust_mutex_init(pthread_mutex_t *mtx)
{
    int32_t ret;
    pthread_mutexattr_t attr;

    if (mtx == NULL) {
        tloge("invalid mtx\n");
        return -1;
    }

    (void)pthread_mutexattr_init(&attr);
    if (pthread_mutexattr_setrobust(&attr, 1) != 0) {
        tloge("set robust failed\n");
        goto err;
    }

    if (pthread_mutexattr_setpshared(&attr, 1) != 0) {
        tloge("set pshared failed\n");
        goto err;
    }

    ret = pthread_mutex_init(mtx, &attr);
    if (ret != 0) {
        tloge("pthread mutex init failed with ret:%d\n", ret);
        goto err;
    }

    (void)pthread_mutexattr_destroy(&attr);
    return 0;

err:
    (void)pthread_mutexattr_destroy(&attr);
    return -1;
}

int32_t get_lock_time(uint32_t timeout_ms, struct timespec *timeout)
{
    struct timespec cur = {0};

    if (timeout == NULL) {
        tloge("invalid timeout\n");
        return -1;
    }

    timeout->tv_sec = timeout_ms / MS_PER_SECONDS;
    timeout->tv_nsec = (timeout_ms % MS_PER_SECONDS) * NS_PER_MSEC;

    clock_gettime(CLOCK_REALTIME, &cur);

    if ((cur.tv_sec + timeout->tv_sec < cur.tv_sec) ||
        (cur.tv_nsec + timeout->tv_nsec < cur.tv_nsec)) {
        tloge("invalid timeout_ms:0x%x\n", timeout_ms);
        return -1;
    }

    timeout->tv_sec += cur.tv_sec;
    timeout->tv_nsec += cur.tv_nsec;
    if (timeout->tv_sec + 1 < timeout->tv_sec) {
        tloge("invalid timeout tv_sec:0x%x\n", timeout->tv_sec);
        return -1;
    }

    if (timeout->tv_nsec >= NS_PER_SECONDS) {
        timeout->tv_nsec -= NS_PER_SECONDS;
        timeout->tv_sec += 1;
    }

    return 0;
}

#define DRV_LOCK_TIMEOUT 20
static int32_t get_timeout_mutex(pthread_mutex_t *mtx)
{
    struct timespec timeout = {0};
    if (mtx == NULL) {
        tloge("invalid mtx\n");
        return -1;
    }

    int32_t ret = get_lock_time(DRV_LOCK_TIMEOUT, &timeout);
    if (ret != 0) {
        tloge("get lock time failed\n");
        return -1;
    }

    ret = pthread_mutex_timedlock(mtx, &timeout);
    if (ret == ETIMEDOUT) {
        tloge("get mutex timeout:%d\n", DRV_LOCK_TIMEOUT);
        return -1;
    }

    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        return pthread_mutex_consistent(mtx);

    return ret;
}

int32_t module_control_init(void)
{
    int32_t i;
    for (i = 0; i < DRV_MODULE_MAX_ID; i++) {
        pthread_mutex_t *mtx = &g_module_control[i].mtx;
        int32_t ret = robust_mutex_init(mtx);
        if (ret != 0) {
            hm_error("module control:%d init failed\n", i);
            return ret;
        }

        g_module_control[i].open_flag = false;
        g_module_control[i].call_pid = INVALID_CALLER_PID;
        g_module_control[i].fn = NULL;
    }

    return 0;
}

static int32_t check_module_call_valid(uint64_t drv_cmd, const struct module_control *module,
    const struct drv_param *params)
{
    if ((drv_cmd == CALL_DRV_OPEN) && module->open_flag) {
        tloge("this module has been opened, cannot open again\n");
        return -1;
    }

    if (((drv_cmd == CALL_DRV_IOCTL) || (drv_cmd == CALL_DRV_CLOSE)) &&
        ((!module->open_flag) || (params->caller_pid != module->call_pid))) {
        tloge("this module cannot ioctl or close by task:0x%x module pid:0x%x\n",
            params->caller_pid, module->call_pid);
        return -1;
    }

    return 0;
}

static int32_t register_call_back(int32_t drv_id)
{
    uint32_t ret = task_register_devrelcb((dev_release_callback)drv_call_back_close_func,
        (void *)(uintptr_t)drv_id);
    if (ret != SRE_OK) {
        tloge("register failed\n");
        return -1;
    }

    return 0;
}

static void unregister_call_back(int32_t drv_id)
{
    task_unregister_devrelcb((dev_release_callback)drv_call_back_close_func,
        (void *)(uintptr_t)drv_id);
}

static int32_t vendor_close_fn(const struct syscall_entry *fn_entry, struct module_control *module,
    int32_t drv_id)
{
    int32_t fn_ret = fn_entry->close_fn((uint32_t)drv_id);
    if (fn_ret != 0) {
        tloge("call close fn failed ret:0x%x\n", fn_ret);
        return fn_ret;
    }

    module->open_flag = false;
    module->call_pid = INVALID_CALLER_PID;
    module->fn = NULL;
    unregister_call_back(drv_id);

    return 0;
}

static int32_t vendor_syscall_dispatch(const struct syscall_entry *fn_entry,
    int32_t drv_id, const struct drv_param *params)
{
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    uint64_t drv_cmd = args[DRV_MODULE_ID_INDEX];
    int32_t fn_ret = -1;

    if ((drv_id < MDRV_MODULE_ID_0) || (drv_id > MDRV_MODULE_ID_15)) {
        tloge("invalid drv_id:0x%x\n", drv_id);
        return -1;
    }

    struct module_control *module = &g_module_control[drv_id - MDRV_MODULE_ID_0];
    int32_t ret = get_timeout_mutex(&module->mtx);
    if (ret != 0) {
        tloge("get drv:%d lock failed\n", drv_id);
        return -1;
    }

    ret = check_module_call_valid(drv_cmd, module, params);
    if (ret != 0)
        goto unlock_mtx;

    if ((drv_cmd == CALL_DRV_OPEN) && (fn_entry->open_fn != NULL)) {
        if (register_call_back(drv_id) != 0)
            goto unlock_mtx;

        if (fn_entry->open_fn((uint32_t)drv_id, args[DRV_OPEN_PARAM_INDEX]) != 0) {
            tloge("open failed\n");
            unregister_call_back(drv_id);
            goto unlock_mtx;
        }
        module->open_flag = true;
        module->call_pid = params->caller_pid;
        module->fn = fn_entry;
        fn_ret = drv_id;
    } else if ((drv_cmd == CALL_DRV_IOCTL) && (fn_entry->invoke_fn != NULL)) {
        fn_ret = fn_entry->invoke_fn((uint32_t)drv_id, (uint32_t)args[DRV_INVOKE_CMD_INDEX],
            (unsigned long)args[DRV_INVOKE_CMD_PARAM_INDEX]);
    } else if ((drv_cmd == CALL_DRV_CLOSE) && (fn_entry->close_fn != NULL)) {
        fn_ret = vendor_close_fn(fn_entry, module, drv_id);
    } else {
        tloge("not support\n");
    }

unlock_mtx:
    ret = pthread_mutex_unlock(&module->mtx);
    if (ret != 0)
        tloge("unlock drv:%d lock failed\n", drv_id);

    return fn_ret;
}

static void call_module_close_func(uint32_t index)
{
    uint32_t drv_id = MDRV_MODULE_ID_0 + index;
    const struct syscall_entry *fn = g_module_control[index].fn;
    if ((fn != NULL) && (fn->close_fn != NULL)) {
        int32_t ret = fn->close_fn(drv_id);
        if (ret != 0) {
            tloge("call back drv:0x%x close fn failed\n", drv_id);
        } else {
            g_module_control[index].open_flag = false;
            g_module_control[index].call_pid = INVALID_CALLER_PID;
            g_module_control[index].fn = NULL;
        }
    }
}

/*
 * register data declare drv_id
 * used as number, not pointer
 */
int32_t drv_call_back_close_func(void *data)
{
    uintptr_t drv_id = (uintptr_t)data;
    if (drv_id < MDRV_MODULE_ID_0 || drv_id > MDRV_MODULE_ID_15) {
        tloge("drv_id:0x%x failed\n", drv_id);
        return -1;
    }

    uint32_t drv_index = drv_id - MDRV_MODULE_ID_0;
    pthread_mutex_t *mtx = &g_module_control[drv_index].mtx;
    int32_t ret = get_timeout_mutex(mtx);
    if (ret != 0) {
        tloge("get drv:0x%x mutex failed:0x%x\n", drv_id, ret);
        return -1;
    }

    call_module_close_func(drv_index);

    ret = pthread_mutex_unlock(mtx);
    if (ret != 0)
        tloge("unlock drv:0x%x lock failed:0x%x\n", drv_id, ret);

    return 0;
}

int32_t get_callerpid_and_job_handler(pid_t *call_pid, uint64_t *job_handler)
{
    tid_t tid;
    if (call_pid == NULL || job_handler == NULL) {
        tloge("invalid param\n");
        return -1;
    }

    int32_t ret = hm_gettid(&tid);
    if (ret != 0) {
        tloge("get tid failed\n");
        return -1;
    }

    ret = get_callerpid_and_job_handler_by_tid(tid, call_pid, job_handler);
    if (ret != 0) {
        tloge("get call pid and job hanlder failed\n");
        return -1;
    }

    return 0;
}

static int32_t vendor_syscall_fn_continue(const struct syscall_entry *fn_entry, int32_t swi_id,
                                          struct drv_param *params, uint64_t permissions)
{
    int32_t ret;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(MDRV_MODULE_ID_8, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_9, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_10, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_11, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_12, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_13, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_14, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_15, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;
    default:
        tloge("no driver can handle swi_id:0x%x\n", swi_id);
        return -1;
    }

    return 0;
}

int32_t vendor_syscall_fn(const struct syscall_entry *fn_entry, int32_t swi_id,
                          struct drv_param *params, uint64_t permissions)
{
    int32_t ret;

    if (params == NULL || params->args == 0 || fn_entry == NULL)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(MDRV_MODULE_ID_0, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_1, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_2, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_3, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_4, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_5, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_6, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

        SYSCALL_PERMISSION(MDRV_MODULE_ID_7, permissions, GENERAL_GROUP_PERMISSION)
        ret = vendor_syscall_dispatch(fn_entry, swi_id, params);
        args[0] = ret;
        SYSCALL_END;

    default:
        return vendor_syscall_fn_continue(fn_entry, swi_id, params, permissions);
    }

    return 0;
}
