/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: rtc timer syscall function
 * Create: 2021-05-27
 */
#include <sys_timer.h>
#include <timer_types.h>
#include <drv_call_check.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <rtc_timer_event.h>
#include <procmgr_ext.h>
#include <hmlog.h>

typedef uint32_t (*timer_syscall_func)(struct call_params *param);

struct syscall_node {
    uint64_t expect_perm;
    timer_syscall_func func;
};

#define SWI_ID_INDEX(swi_id) ((swi_id) - SW_SYSCALL_TIMER_BASE)

static int32_t get_uuid_by_pid(struct call_params *param)
{
    int32_t ret;
    struct spawn_uuid sp_uuid;

    ret = hm_getuuid(param->pid, &sp_uuid);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("get spawn uuid failed\n");
        return TMR_DRV_ERROR;
    }

    ret = memcpy_s(&param->sys_id.uuid, sizeof(param->sys_id.uuid), &sp_uuid.uuid, sizeof(sp_uuid.uuid));
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("failed to memcpy uuid\n");
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

static uint32_t create_timer_call(struct call_params *param)
{
    int32_t ret;
    uint64_t *t_event = NULL;
    timer_event *timer_event_handle = NULL;

    param->mmaped_ptr_cnt = 2; /* map params num 2 */
    param->addr_type = A64;
    param->mmaped_ptrs[0].addr.addr_64 = param->args[0];
    param->mmaped_ptrs[0].len = sizeof(uint64_t);
    param->mmaped_ptrs[0].access_flag = ACCESS_WRITE_RIGHT;

    param->mmaped_ptrs[1].addr.addr_64 = param->args[1];
    param->mmaped_ptrs[1].len = sizeof(struct timer_private_data_kernel);
    param->mmaped_ptrs[1].access_flag = ACCESS_READ_RIGHT;
    ret = check_addr_access_right(param);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("cmd 0x%x:access_right check failed\n", param->swi_id);
        unmap_maped_ptrs(param);
        return TMR_DRV_ERROR;
    }

    t_event = (uintptr_t)param->mmaped_ptrs[0].addr.addr_64;
    param->args[1] = param->mmaped_ptrs[1].addr.addr_64;
    timer_event_handle = timer_event_create(NULL, TIMER_RTC, (void *)(uintptr_t)(param->args[1]),
                                            &(param->sys_id.uuid));
    *t_event = (uintptr_t)timer_event_handle;

    unmap_maped_ptrs(param);
    param->args[0] = TMR_DRV_SUCCESS;
    return TMR_DRV_SUCCESS;
}

static uint32_t start_timer_call(struct call_params *param)
{
    int32_t ret;

    param->mmaped_ptr_cnt = 1;
    param->addr_type = A64;
    param->mmaped_ptrs[0].addr.addr_64 = param->args[1];
    param->mmaped_ptrs[0].len = sizeof(timeval_t);
    param->mmaped_ptrs[0].access_flag = ACCESS_WRITE_RIGHT;

    ret = check_addr_access_right(param);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("cmd %x:access_right check failed\n", param->swi_id);
        unmap_maped_ptrs(param);
        return TMR_DRV_ERROR;
    }

    param->args[1] = param->mmaped_ptrs[0].addr.addr_64;
    uint32_t uret = timer_event_start((timer_event *)(uintptr_t)(param->args[0]),
                                      (timeval_t *)(uintptr_t)(param->args[1]), &(param->sys_id.uuid));

    unmap_maped_ptrs(param);
    param->args[0] = uret;
    return TMR_DRV_SUCCESS;
}

static uint32_t destory_timer_call(struct call_params *param)
{
    uint32_t ret;

    ret = timer_event_destory_with_uuid((timer_event *)(uintptr_t)(param->args[0]),
                                        &(param->sys_id.uuid), false);
    param->args[0] = ret;

    return TMR_DRV_SUCCESS;
}

static uint32_t stop_timer_call(struct call_params *param)
{
    uint32_t ret;

    ret = timer_event_stop((timer_event *)(uintptr_t)(param->args[0]), &(param->sys_id.uuid), false);
    param->args[0] = ret;

    return TMR_DRV_SUCCESS;
}

static uint32_t get_timer_expire_call(struct call_params *param)
{
    int64_t timer_value;
    uint64_t *expire_value = NULL;
    uint32_t ret;

    param->mmaped_ptr_cnt = 1;
    param->addr_type = A64;
    param->mmaped_ptrs[0].addr.addr_64 = param->args[1];
    param->mmaped_ptrs[0].len = sizeof(uint64_t);
    param->mmaped_ptrs[0].access_flag = ACCESS_WRITE_RIGHT;

    ret = check_addr_access_right(param);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("cmd %x:access_right check failed\n", param->swi_id);
        unmap_maped_ptrs(param);
        return TMR_DRV_ERROR;
    }

    expire_value = (uintptr_t)param->mmaped_ptrs[0].addr.addr_64;
    timer_value = timer_expire_value_get((timer_event *)(uintptr_t)param->args[0], false);
    *expire_value = timer_value;
    param->args[0] = TMR_DRV_SUCCESS;
    unmap_maped_ptrs(param);

    return TMR_DRV_SUCCESS;
}

static uint32_t check_timer_call(struct call_params *param)
{
    int32_t ret;

    param->mmaped_ptr_cnt = 1;
    param->addr_type = A64;
    param->mmaped_ptrs[0].addr.addr_64 = param->args[0];
    param->mmaped_ptrs[0].len = sizeof(timer_notify_data_kernel);
    param->mmaped_ptrs[0].access_flag = ACCESS_WRITE_RIGHT;

    ret = check_addr_access_right(param);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("cmd %x:access_right check failed\n", param->swi_id);
        unmap_maped_ptrs(param);
        return TMR_DRV_ERROR;
    }

    param->args[0] = param->mmaped_ptrs[0].addr.addr_64;
    uint32_t uret = timer_data_check_by_uuid((timer_notify_data_kernel *)(uintptr_t)param->args[0],
                                             &(param->sys_id.uuid));
    unmap_maped_ptrs(param);
    param->args[0] = uret;
    return TMR_DRV_SUCCESS;
}

static uint32_t get_rtc_time_call(struct call_params *param)
{
    param->args[0] = (uint64_t)timer_rtc_value_get();
    return TMR_DRV_SUCCESS;
}

static uint32_t set_timer_permission(const TEE_UUID *uuid, uint64_t permission)
{
    TEE_Result ret;

    if (uuid == NULL) {
        hm_error("invalid uuid for setting permission\n");
        return TMR_DRV_ERROR;
    }

    ret = add_ta_permission((TEE_UUID *)uuid, permission);
    if (ret != TEE_SUCCESS) {
        hm_error("set timer permission failed!\n");
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

static uint32_t set_timer_perm_call(struct call_params *param)
{
    int32_t ret;

    param->mmaped_ptr_cnt = 1;
    param->addr_type = A64;
    param->mmaped_ptrs[0].addr.addr_64 = param->args[0];
    param->mmaped_ptrs[0].len = sizeof(param->sys_id.uuid);
    param->mmaped_ptrs[0].access_flag = ACCESS_WRITE_RIGHT;

    ret = check_addr_access_right(param);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("set timer cmd %x:access_right check failed\n", param->swi_id);
        unmap_maped_ptrs(param);
        return TMR_DRV_ERROR;
    }

    param->args[0] = param->mmaped_ptrs[0].addr.addr_64;
    uint32_t uret = set_timer_permission((const TEE_UUID *)(uintptr_t)param->args[0], param->args[1]);

    unmap_maped_ptrs(param);
    param->args[0] = uret;

    return TMR_DRV_SUCCESS;
}

static const struct syscall_node g_syscall_tbl[] = {
    [SWI_ID_INDEX(SW_SYSCALL_TIMER_CREATE)]         = { TIMER_GROUP_PERMISSION, create_timer_call },
    [SWI_ID_INDEX(SW_SYSCALL_TIMER_START)]          = { TIMER_GROUP_PERMISSION, start_timer_call },
    [SWI_ID_INDEX(SW_SYSCALL_TIMER_DESTORY)]        = { TIMER_GROUP_PERMISSION, destory_timer_call },
    [SWI_ID_INDEX(SW_SYSCALL_TIMER_STOP)]           = { TIMER_GROUP_PERMISSION, stop_timer_call },
    [SWI_ID_INDEX(SW_SYSCALL_GET_TIMER_EXPIRE)]     = { TIMER_GROUP_PERMISSION, get_timer_expire_call },
    [SWI_ID_INDEX(SW_SYSCALL_CHECK_TIMER)]          = { TIMER_GROUP_PERMISSION, check_timer_call },
    [SWI_ID_INDEX(SW_SYSCALL_GET_RTC_TIME)]         = { GENERAL_GROUP_PERMISSION, get_rtc_time_call },
    [SWI_ID_INDEX(SW_SYSCALL_SET_TIMER_PERMISSION)] = { TASK_GROUP_PERMISSION, set_timer_perm_call },
    [SWI_ID_INDEX(SW_SYSCALL_TIMER_MAX)]            = { 0, NULL },
};

static bool check_permission(int32_t sw_id, uint64_t permissions, uint64_t expect_perm)
{
    if ((expect_perm & permissions) != expect_perm) {
        hm_error("permission denied to access swi_id 0x%x\n", sw_id);
        audit_fail_syscall();
        return false;
    }
    return true;
}

static uint32_t syscall_common(int32_t swi_id, const struct drv_param *params, uint64_t permissions,
                               uint64_t expect_perm, const timer_syscall_func func)
{
    uint32_t ret;
    struct call_params map_param = {0};
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    if (params == NULL || func == NULL) {
        hm_error("invalid input param\n");
        return TMR_DRV_ERROR;
    }

    ret = check_call_permission(permissions, expect_perm);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", swi_id);
        return TMR_DRV_ERROR;
    }

    map_param.swi_id = swi_id;
    map_param.pid = params->pid;
    map_param.self_pid = hm_getpid();
    map_param.args = args;
    map_param.job_handler = params->job_handler;
    ret = get_uuid_by_pid(&map_param);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("rtc driver get uuid fail\n");
        return TMR_DRV_ERROR;
    }

    ret = func(&map_param);
    return ret;
}

int32_t rtc_timer_syscall(int32_t swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret;
    uint32_t idx;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    if (params == NULL) {
        hm_error("invalid input param\n");
        return TMR_DRV_ERROR;
    }

    if (swi_id <= SW_SYSCALL_TIMER_BASE || swi_id >= (SW_SYSCALL_TIMER_MAX))
        return TMR_DRV_ERROR;

    idx = SWI_ID_INDEX(swi_id);
    if (idx > (sizeof(g_syscall_tbl) / sizeof(g_syscall_tbl[0])) || g_syscall_tbl[idx].func == NULL) {
        hm_error("rtc timer syscall id 0x%x idx %d\n", swi_id, idx);
        return TMR_DRV_ERROR;
    }

    ret = syscall_common(swi_id, params, permissions, g_syscall_tbl[idx].expect_perm, g_syscall_tbl[idx].func);
    if (ret != TMR_DRV_SUCCESS)
        args[0] = ret;

    return TMR_DRV_SUCCESS;
}
