/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Init function in timer
 * Create: 2019-08-20
 */
#include "timer_init.h"
#include <stdio.h>
#include <stdlib.h>
#include <securec.h>
#include <errno.h>
#include <cs.h>
#include <kernel/cspace.h>
#include <hm_msg_type.h>
#include <hm_mman_ext.h>
#include <hmlog.h>
#include <sys/usrsyscall_ext.h>
#include <irqmgr.h>
#include <procmgr_ext.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <iomgr_ext.h>
#include <ta_permission.h>
#include <ac.h>
#include <ipclib.h>
#include <pm_msgtype.h>
#include <sys_timer.h>
#include <timer_interrupt.h>
#include <timer_event.h>
#include <timer_pm.h>
#include <timer_desc.h>
#include <drv_module.h>
#include "mem_drv_map.h"
#include <inttypes.h>

#ifdef CONFIG_RTC_TIMER
#include <timer_rtc.h>
#endif

#ifdef TIMER_PERMISSION_DISABLE
#undef TIMER_GROUP_PERMISSION
#define TIMER_GROUP_PERMISSION GENERAL_GROUP_PERMISSION
#endif

#include <timer_hw.h>
#include <timer.h>
#include <drv_call_check.h>
#include <drv_pm_check.h>
#include "timer_types.h"
#include "timer_sys.h"
#include "timer_io_map.h"
#include "crypto_hal.h"

#define INVALID_CALLERPID       (-1)
#define TMR_INITED              0x1
#define TMR_TCB_UNINITED        0x0
#define MAX_TIMES_GENERATE_SEED 2

static int32_t g_timer_inited;
static cref_t g_timer_tcb_cref;
static pid_t g_caller_pid = INVALID_CALLERPID;
static uint32_t g_mix_seed;

pid_t get_g_caller_pid(void)
{
    return g_caller_pid;
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

uint32_t get_mix_seed(void)
{
    uint32_t seed = 0;
#ifdef DX_ENABLE
    uint32_t count = 0;
    uint32_t ret;

    if (g_mix_seed != 0)
        return g_mix_seed;

    while (count < MAX_TIMES_GENERATE_SEED) { /* test MAX_TIMES_GENERATE_SEED times, in case of seed = 0 */
        count++;
        ret = (uint32_t)tee_crypto_generate_random((uint8_t *)&seed, sizeof(seed), true);
        if ((ret != TMR_DRV_SUCCESS) || (seed == 0))
            continue;

        g_mix_seed = seed;
        break;
    }
#else
    g_mix_seed = seed;
#endif
    return g_mix_seed;
}

uint32_t timer_drv_init(void)
{
    uint32_t seed;

    /* avoid TA get the seed */
    seed = get_mix_seed();
    if (seed != 0)
        return TMR_DRV_SUCCESS;

    return TMR_DRV_ERROR;
}

static int32_t get_uuid_by_pid(struct timer_sys_id *sys_id)
{
    int32_t ret;
    struct spawn_uuid sp_uuid;
    errno_t ret_s;

    ret = hm_getuuid(sys_id->pid, &sp_uuid);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("get spawn sys_id->uuid failed\n");
        return TMR_DRV_ERROR;
    }

    ret_s = memcpy_s(&sys_id->uuid, sizeof(sys_id->uuid), &sp_uuid.uuid, sizeof(sp_uuid.uuid));
    if (ret_s != EOK) {
        hm_error("failed to memcpy sys_id->uuid\n");
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

static uint32_t get_timer_permission(struct timer_reply_msg_t *rmsg, const struct hmcap_message_info *msginfo,
                                     uint64_t *permissions)
{
    int32_t hm_ret;
    TEE_Result ret;
    uid_t uid;
    uint32_t cnode_idx = msginfo->src_cnode_idx;

    if (cnode_idx == 0) {
        rmsg->header.reply.ret_val = OS_ERROR;
        return TMR_DRV_ERROR;
    }

    hm_ret = ac_get_uid(cnode_idx, &uid);
    if (hm_ret == 0) {
        ret = get_ta_permission_wrapper(uid, permissions);
        if (ret != TEE_SUCCESS) {
            rmsg->header.reply.ret_val = OS_ERROR;
            hm_error("get ta permission failed 0x%x\n", hm_ret);
            return TMR_DRV_ERROR;
        }
    } else {
        hm_error("can not find uid form cnode 0x%x\n", cnode_idx);
        rmsg->header.reply.ret_val = OS_ERROR;
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

static uint32_t get_timer_uuid_and_pid(struct timer_reply_msg_t *rmsg, const struct hmcap_message_info *msginfo,
                                       struct timer_sys_id *sys_id)
{
    int32_t hm_ret;
    uint32_t cnode_idx = msginfo->src_cnode_idx;

    /* get caller sys_id->pid from acmgr and msginfo */
    hm_ret = ac_get_pid(cnode_idx, &sys_id->pid);
    if (hm_ret != 0) {
        hm_error("get sys_id->pid failed for cnode_idx %u\n", cnode_idx);
        rmsg->header.reply.ret_val = OS_ERROR;
        return TMR_DRV_ERROR;
    }
    g_caller_pid = hmpid_to_pid(TCBCREF2TID(msginfo->src_tcb_cref), (uint32_t)sys_id->pid);

    hm_ret = get_uuid_by_pid(sys_id);
    if (hm_ret != TMR_DRV_SUCCESS) {
        hm_error("get sys_id->uuid failed\n");
        rmsg->header.reply.ret_val = OS_ERROR;
        return TMR_DRV_ERROR;
    }

    return TMR_DRV_SUCCESS;
}

static uint32_t read_time_stamp_call(uint64_t current_permission, struct call_params *param)
{
    int64_t timer_value;
    int32_t ret;

    ret = check_call_permission(current_permission, GENERAL_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    timer_value = timer_stamp_value_read();
    param->regs->r0 = LOWER_32_BITS(timer_value); /* get the low 32 bits */
    param->regs->r1 = UPPER_32_BITS(timer_value); /* high 32 bits */

    return TMR_DRV_SUCCESS;
}

static uint32_t init_rtc_time_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;

    ret = check_call_permission(current_permission, TASK_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    hm_debug("[TIME MANAGER] startup kernel time: 0x%llx\n", param->regs->r0);
    init_startup_time_kernel((uint32_t)param->regs->r0);

    return TMR_DRV_SUCCESS;
}

static uint32_t adjust_sys_time_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;

    ret = check_call_permission(current_permission, TASK_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id = 0x%x\n", param->swi_id);
        return ret;
    }

    if (param->regs->r0 > INT32_MAX || param->regs->r1 > INT32_MAX) {
        hm_error("time param overflow\n");
        return TMR_DRV_ERROR;
    }

    struct tee_time_t time = { (int32_t)param->regs->r0, (int32_t)param->regs->r1 };
    adjust_sys_time(&time);

    return TMR_DRV_SUCCESS;
}

static uint32_t get_startup_time_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;

    ret = check_call_permission(current_permission, TASK_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("get start time permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    struct tee_time_t time = { 0, 0 };

    get_sys_startup_time(&time, (uint32_t *)&(param->regs->r2));
    hm_debug("[TIME MANAGER] start time: 0x%llx\n", param->regs->r2);
    param->regs->r0 = (uint64_t)time.seconds;
    param->regs->r1 = (uint64_t)time.millis;
    return TMR_DRV_SUCCESS;
}

static uint32_t gen_sys_date_time_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;

    ret = check_call_permission(current_permission, GENERAL_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    struct tee_date_t *date_time = malloc(sizeof(struct tee_date_t));
    if (date_time == NULL) {
        hm_error("date time malloc failed\n");
        return TMR_DRV_ERROR;
    }
    (void)memset_s(date_time, sizeof(struct tee_date_t), 0, sizeof(struct tee_date_t));

    gen_sys_date_time((uint32_t)param->regs->r0, date_time);

    ret = copy_to_sharemem((uintptr_t)date_time, sizeof(struct tee_date_t), (uint32_t)param->pid,
                           param->regs->r1, sizeof(struct tee_date_t));
    if (ret != 0) {
        hm_error("copy to sharemem date time failed\n");
        free(date_time);
        date_time = NULL;
        return TMR_DRV_ERROR;
    }

    free(date_time);
    date_time = NULL;
    return TMR_DRV_SUCCESS;
}

static uint32_t read_timer_count_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;

    ret = check_call_permission(current_permission, GENERAL_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    hm_debug("[TIME MANAGER] sleep: %u\n", (uint32_t)param->regs->r0);
    param->regs->r0 = timer_free_running_value_get();

    return TMR_DRV_SUCCESS;
}

static uint32_t get_sys_rtc_time_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;
    struct tee_time_t time = { 0, 0 };

    ret = check_call_permission(current_permission, GENERAL_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("get rtc time permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    get_sys_rtc_time_kernel(&time);

    param->regs->r0 = (uint64_t)time.seconds;
    param->regs->r1 = (uint64_t)time.millis;
    return TMR_DRV_SUCCESS;
}

static uint32_t get_sys_rtc_offset_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;
    struct tee_time_t time = { 0, 0 };

    ret = check_call_permission(current_permission, GENERAL_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("get rtc offset permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    get_sys_rtc_time_offset(&time);

    param->regs->r0 = (uint64_t)time.seconds;
    param->regs->r1 = (uint64_t)time.millis;

    return TMR_DRV_SUCCESS;
}

#ifdef TIMER_EVENT_SUPPORT
static uint32_t create_timer_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;
    int32_t timer_class;
    timer_event *timer_event_handle = NULL;
    struct timer_private_data_kernel *priv_data = NULL;

    ret = check_call_permission(current_permission, TIMER_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    if (param->regs->r1 > INT32_MAX) {
        hm_error("timer class overflow\n");
        return TMR_DRV_ERROR;
    }

    timer_class = (int32_t)param->regs->r1;
    if (timer_class != TIMER_CLASSIC) {
        priv_data = malloc(sizeof(struct timer_private_data_kernel));
        if (priv_data == NULL) {
            hm_error("timer private data malloc failed\n");
            return TMR_DRV_ERROR;
        }
        ret = copy_from_sharemem((uint32_t)param->pid, param->regs->r2, sizeof(struct timer_private_data_kernel),
            (uintptr_t)priv_data, sizeof(struct timer_private_data_kernel));
        if (ret != 0) {
            hm_error("timer private data copy failed\n");
            free(priv_data);
            priv_data = NULL;
            return TMR_DRV_ERROR;
        }
    }
    timer_event_handle = timer_event_create((sw_timer_event_handler)(uintptr_t)(param->regs->r0),
                                            timer_class, (void *)priv_data, param->sys_id.pid);
    if (timer_event_handle != NULL)
        param->regs->r0 = (uintptr_t)timer_event_handle;
    else
        param->regs->r0 = NULL_ENENT_HANDLER;

    if (timer_class != TIMER_CLASSIC) {
        free(priv_data);
        priv_data = NULL;
    }
    return TMR_DRV_SUCCESS;
}

static uint32_t start_timer_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;
    timeval_t time;

    ret = check_call_permission(current_permission, TIMER_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    if (param->regs->r1 > INT64_MAX) {
        hm_error("start_timer_call param overflow\n");
        param->regs->r0 = TMR_DRV_ERROR;
        return TMR_DRV_ERROR;
    }

    time.tval64 = (int64_t)param->regs->r1;
    uint32_t uret = timer_event_start((timer_event *)(uintptr_t)(param->regs->r0),
                                      &time, &(param->sys_id.uuid));
    param->regs->r0 = uret;

    return uret;
}

static uint32_t destory_timer_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;

    ret = check_call_permission(current_permission, TIMER_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }
    uint32_t uret = timer_event_destory_with_uuid((timer_event *)(uintptr_t)(param->regs->r0),
                                                  &(param->sys_id.uuid), false);
    param->regs->r0 = uret;

    return uret;
}

static uint32_t stop_timer_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;

    ret = check_call_permission(current_permission, TIMER_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }
    uint32_t uret = timer_event_stop((timer_event *)(uintptr_t)(param->regs->r0), &(param->sys_id.uuid), false);
    param->regs->r0 = uret;

    return uret;
}

static uint32_t get_timer_expire_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;
    int64_t timer_value;

    ret = check_call_permission(current_permission, TIMER_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    timer_value = timer_expire_get((timer_event *)(uintptr_t)param->regs->r0);
    param->regs->r1 = LOWER_32_BITS((uint64_t)timer_value); /* get the low 32 bits */
    param->regs->r2 = UPPER_32_BITS((uint64_t)timer_value); /* shift 32 bits to right */

    return TMR_DRV_SUCCESS;
}

static uint32_t check_timer_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;

    ret = check_call_permission(current_permission, TIMER_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    timer_notify_data_kernel *timer_data = malloc(sizeof(timer_notify_data_kernel));
    if (timer_data == NULL) {
        hm_error("malloc timer data failed\n");
        return TMR_DRV_ERROR;
    }
    (void)memset_s(timer_data, sizeof(timer_notify_data_kernel), 0, sizeof(timer_notify_data_kernel));

    ret = copy_from_sharemem((uint32_t)param->pid, param->regs->r0, sizeof(timer_notify_data_kernel),
        (uintptr_t)timer_data, sizeof(timer_notify_data_kernel));
    if (ret != 0) {
        hm_error("copy timer data sharemem failed\n");
        free(timer_data);
        timer_data = NULL;
        return TMR_DRV_ERROR;
    }

    uint32_t uret = timer_data_check_by_uuid(timer_data, &(param->sys_id.uuid));
    ret = copy_to_sharemem((uintptr_t)timer_data, sizeof(timer_notify_data_kernel), (uint32_t)param->pid,
                           param->regs->r0, sizeof(timer_notify_data_kernel));
    if (ret != 0) {
        hm_error("copy to timer data sharemem failed\n");
        free(timer_data);
        timer_data = NULL;
        return TMR_DRV_ERROR;
    }
    param->regs->r0 = uret;
    free(timer_data);
    timer_data = NULL;

    return uret;
}

static uint32_t init_timer_drv_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;

    ret = check_call_permission(current_permission, TASK_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    param->regs->r0 = timer_drv_init();

    return TMR_DRV_SUCCESS;
}

static uint32_t release_timer_event_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;

    ret = check_call_permission(current_permission, TASK_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("release time event permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    TEE_UUID *uuid = malloc(sizeof(TEE_UUID));
    if (uuid == NULL) {
        hm_error("uuid malloc failed\n");
        return TMR_DRV_ERROR;
    }
    ret = copy_from_sharemem((uint32_t)param->pid, param->regs->r0, sizeof(TEE_UUID),
        (uintptr_t)uuid, sizeof(TEE_UUID));
    if (ret != 0) {
        hm_error("copy uuid from sharemem failed\n");
        free(uuid);
        uuid = NULL;
        return TMR_DRV_ERROR;
    }
    uint32_t uret = release_timer_event_by_uuid(uuid);
    param->regs->r0 = uret;

    free(uuid);
    uuid = NULL;
    return uret;
}
#endif

#ifdef CONFIG_RTC_TIMER
static uint32_t get_rtc_time_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;

    ret = check_call_permission(current_permission, GENERAL_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    param->regs->r0 = (uint64_t)timer_rtc_value_get();
    return TMR_DRV_SUCCESS;
}
#endif

static uint32_t get_sys_date_time_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;

    ret = check_call_permission(current_permission, GENERAL_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    struct tee_date_t *date_time = malloc(sizeof(struct tee_date_t));
    if (date_time == NULL) {
        hm_error("date_time malloc failed\n");
        param->regs->r0 = TMR_DRV_ERROR;
        return TMR_DRV_ERROR;
    }
    (void)memset_s(date_time, sizeof(struct tee_date_t), 0, sizeof(struct tee_date_t));

    uint32_t uret = drv_get_sys_date_time(date_time);
    if (uret != TMR_DRV_SUCCESS) {
        hm_error("drv_get_sys_date_time failed\n");
        goto out;
    }

    ret = copy_to_sharemem((uintptr_t)date_time, sizeof(struct tee_date_t), (uint32_t)param->pid,
                           param->regs->r0, sizeof(struct tee_date_t));
    if (ret != 0) {
        hm_error("copy to sharemem date time failed\n");
        uret = TMR_DRV_ERROR;
    }

out:
    free(date_time);
    date_time = NULL;
    param->regs->r0 = uret;
    return uret;
}

static uint32_t set_timer_perm_call(uint64_t current_permission, struct call_params *param)
{
    int32_t ret;

    ret = check_call_permission(current_permission, PERMSRV_GROUP_PERMISSION);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("set timer permission denied to access swi_id 0x%x\n", param->swi_id);
        return ret;
    }

    TEE_UUID *temp_uuid = malloc(sizeof(TEE_UUID));
    if (temp_uuid == NULL) {
        hm_error("uuid malloc failed\n");
        return TMR_DRV_ERROR;
    }
    ret = copy_from_sharemem((uint32_t)param->pid, param->regs->r0, sizeof(TEE_UUID),
        (uintptr_t)temp_uuid, sizeof(TEE_UUID));
    if (ret != 0) {
        hm_error("copy uuid from sharemem failed\n");
        free(temp_uuid);
        temp_uuid = NULL;
        return TMR_DRV_ERROR;
    }
    uint32_t uret = set_timer_permission(temp_uuid, param->regs->r1);
    param->regs->r0 = uret;

    free(temp_uuid);
    temp_uuid = NULL;
    return uret;
}

#define SWI_ID_INDEX(swi_id) ((swi_id) - SW_SYSCALL_TIMER_BASE)
typedef uint32_t (*timer_syscall_func)(uint64_t current_permission, struct call_params *param);
static timer_syscall_func g_timer_syscall_func_list[] = {
    [SWI_ID_INDEX(SW_SYSCALL_TIMER_BASE)]               = NULL,
    [SWI_ID_INDEX(SW_SYSCALL_TIMER_READSTAMP)]          = read_time_stamp_call,
    [SWI_ID_INDEX(SW_SYSCALL_INIT_RTC_TIME)]            = init_rtc_time_call,
    [SWI_ID_INDEX(SW_SYSCALL_ADJUST_SYS_TIME)]          = adjust_sys_time_call,
    [SWI_ID_INDEX(SW_SYSCALL_GET_STARTUP_TIME)]         = get_startup_time_call,
    [SWI_ID_INDEX(SW_SYSCALL_GEN_SYS_DATE_TIME)]        = gen_sys_date_time_call,
    [SWI_ID_INDEX(SW_SYSCALL_READ_TIMER_COUNT)]         = read_timer_count_call,
    [SWI_ID_INDEX(SW_SYSCALL_GET_SYS_RTC_TIME_KERNEL)]  = get_sys_rtc_time_call,
    [SWI_ID_INDEX(SW_SYSCALL_GET_SYS_RTC_TIME_OFFSET)]  = get_sys_rtc_offset_call,
#ifdef TIMER_EVENT_SUPPORT
    [SWI_ID_INDEX(SW_SYSCALL_TIMER_CREATE)]             = create_timer_call,
    [SWI_ID_INDEX(SW_SYSCALL_TIMER_START)]              = start_timer_call,
    [SWI_ID_INDEX(SW_SYSCALL_TIMER_DESTORY)]            = destory_timer_call,
    [SWI_ID_INDEX(SW_SYSCALL_TIMER_STOP)]               = stop_timer_call,
    [SWI_ID_INDEX(SW_SYSCALL_GET_TIMER_EXPIRE)]         = get_timer_expire_call,
    [SWI_ID_INDEX(SW_SYSCALL_CHECK_TIMER)]              = check_timer_call,
    [SWI_ID_INDEX(SW_SYSCALL_INIT_TIMER_DRV)]           = init_timer_drv_call,
    [SWI_ID_INDEX(SW_SYSCALL_RELEASE_TIMER_EVENT)]      = release_timer_event_call,
#endif
#ifdef CONFIG_RTC_TIMER
    [SWI_ID_INDEX(SW_SYSCALL_GET_RTC_TIME)]             = get_rtc_time_call,
#endif
    [SWI_ID_INDEX(SW_SYSCALL_GET_SYS_DATE_TIME)]        = get_sys_date_time_call,
    [SWI_ID_INDEX(SW_SYSCALL_SET_TIMER_PERMISSION)]     = set_timer_perm_call,
    [SWI_ID_INDEX(SW_SYSCALL_TIMER_MAX)]                = NULL,
};

static uint32_t init_call_param(const struct timer_req_msg_t *msg, struct timer_reply_msg_t *rmsg,
                                const struct hmcap_message_info *msginfo, struct call_params *param)
{
    uint32_t ret;
    struct timer_sys_id sys_id;

    struct msg_args *regs = (void *)&msg->args[0];
    if (regs == NULL) {
        hm_error("regs is NULL\n");
        return TMR_DRV_ERROR;
    }

    ret = get_timer_uuid_and_pid(rmsg, msginfo, &sys_id);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("get timer sys_id.uuid failed!\n");
        return TMR_DRV_ERROR;
    }

    errno_t ret_s = memcpy_s(&(param->sys_id), sizeof(sys_id), &sys_id, sizeof(sys_id));
    if (ret_s != EOK) {
        hm_error("failed to memcpy sys id\n");
        return TMR_DRV_ERROR;
    }

    static pid_t self_pid = 0;
    if (self_pid == 0)
        self_pid = hm_getpid();

    param->swi_id = msg->header.send.msg_id;
    param->regs = regs;
    param->pid = get_g_caller_pid();
    param->self_pid = self_pid;
    param->job_handler = msg->job_handler;

    return TMR_DRV_SUCCESS;
}

static int32_t timer_handle_message(const struct timer_req_msg_t *msg, struct timer_reply_msg_t *rmsg,
                                    const struct hmcap_message_info *msginfo)
{
    uint64_t permissions;
    uint32_t ret;
    struct call_params param = {0};
    rmsg->header.reply.msg_size = (uint32_t) TIMER_REP_MSG_SIZE;

    ret = get_timer_permission(rmsg, msginfo, &permissions);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("get timer permissions failed!\n");
        rmsg->header.reply.ret_val = ret;
        return TMR_DRV_ERROR;
    }

    ret = init_call_param(msg, rmsg, msginfo, &param);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("Failed to init timer call paramters\n");
        rmsg->header.reply.ret_val = ret;
        return TMR_DRV_ERROR;
    }

    if (param.swi_id <= SW_SYSCALL_TIMER_BASE || param.swi_id >= SW_SYSCALL_TIMER_MAX ||
        g_timer_syscall_func_list[SWI_ID_INDEX(param.swi_id)] == NULL) {
        hm_error("Failed to init timer call paramters 0x%x\n", param.swi_id);
        rmsg->header.reply.ret_val = -ENOSYS;
        return -ENOSYS;
    }

    ret = g_timer_syscall_func_list[SWI_ID_INDEX(param.swi_id)](permissions, &param);
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("Failed to handle syscall 0x%x\n", param.swi_id);
        rmsg->header.reply.ret_val = ret;
        unmap_maped_ptrs(&param);
        return TMR_DRV_ERROR;
    }

    rmsg->regs[0] = param.regs->r0;
    rmsg->regs[1] = param.regs->r1;
    rmsg->regs[2] = param.regs->r2;
    rmsg->regs[3] = param.regs->r3;
    rmsg->header.reply.ret_val = ret;
    rmsg->tcb_cref = g_timer_tcb_cref;

    unmap_maped_ptrs(&param);

    return TMR_DRV_SUCCESS;
}

const char *g_pm_sender_name = "tee_drv_server";

static int32_t hunt_sender_drv_pid(uint32_t *pid)
{
    uint32_t ret = ipc_hunt_by_name(0, g_pm_sender_name, pid);
    if (ret != 0) {
        hm_error("get %s pid fail\n", g_pm_sender_name);
        return -1;
    }

    hm_debug("hunt drv:%s succ\n", g_pm_sender_name);

    return 0;
}

static bool check_msg_invalid(uint16_t msg_id, cref_t msg_hdl, hm_msg_header *msg,
    const struct hmcap_message_info *info)
{
    static uint32_t auth_pid = SRE_PID_ERR;
    if (auth_pid == SRE_PID_ERR) {
        int32_t ret = hunt_sender_drv_pid(&auth_pid);
        if (ret != 0)
            return true;
    }

    if (pm_msg_param_check(msg_id, msg_hdl, msg, info, pid_to_hmpid(auth_pid)) != 0)
        return true;

    return false;
}

intptr_t timer_pm_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info)
{
    uint16_t msg_id;
    int32_t err;
    cref_t msg_hdl;

    /*
     * The 'dispatch_fn_t' expect all functions have the paramter 'info'.
     * Actually, this paramter is useless in this function.
     * But we cannot delete it.
     */
    (void)info;

    if ((msg == NULL) || (p_msg_hdl == NULL)) {
        hm_error("timer dispatch param error\n");
        return TMR_DRV_ERROR;
    }

    msg_hdl = *p_msg_hdl;
    msg_id = ((hm_msg_header *)msg)->send.msg_id;
    if (check_msg_invalid(msg_id, msg_hdl, msg, info))
        return TMR_DRV_ERROR;

    hm_debug("timer CPU%d handle PM msg 0x%x start\n", hm_get_current_cpu_id(), msg_id);
    if (msg_id == HM_MSG_ID_DRV_PWRMGR_SUSPEND_CPU)
        tc_drv_sp(TIMER_SUSPEND_S3);
    else if (msg_id == HM_MSG_ID_DRV_PWRMGR_SUSPEND_S4)
        tc_drv_sp(TIMER_SUSPEND_S4);
    else if (msg_id == HM_MSG_ID_DRV_PWRMGR_RESUME_CPU)
        tc_drv_sr(TIMER_RESUME_S3);
    else
        tc_drv_sr(TIMER_RESUME_S4);

    err = cs_server_reply_error(msg_hdl, TMR_DRV_SUCCESS);
    if (err != TMR_DRV_SUCCESS) {
        hm_error("reply to PM msg error %d\n", err);
        return err;
    }
    hm_debug("CPU%d handle PM msg 0x%x done\n", hm_get_current_cpu_id(), msg_id);

    return TMR_DRV_SUCCESS;
}

intptr_t timer_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info)
{
    long ret;
    cref_t msg_hdl;
    struct timer_reply_msg_t rbuf = { {{ 0 }}, 0, { 0 } };

    if ((p_msg_hdl == NULL) || (msg == NULL) || (info == NULL)) {
        hm_error("invalid msg\n");
        return TMR_DRV_ERROR;
    }
    msg_hdl = *p_msg_hdl;

    if (g_timer_inited != TMR_INITED) {
        hm_error("timer's initization is not finished yet!!\n");
        return TMR_DRV_ERROR;
    }

    if (info->msg_size != TIMER_REQ_MSG_SIZE) {
        hm_error("ERROR: Invalid message size\n");
        return TMR_DRV_ERROR;
    }

    ret = timer_handle_message((const struct timer_req_msg_t *)msg, &rbuf, info);
    if (ret != TMR_DRV_SUCCESS)
        hm_error("ERROR: timer message handle failed\n");

    ret = hm_msg_reply(msg_hdl, &rbuf, sizeof(rbuf));
    if (ret != 0) {
        hm_error("reply error return code!!\n");
        return TMR_DRV_ERROR;
    }
    return ret;
}

static int32_t timer_address_map(void)
{
    uint32_t i;
    void *ptr = NULL;

    /* prepare io mmap */
    for (i = 0; i < ARRAY_SIZE(g_timer_id_addr); i++) {
        ptr = hm_io_map(g_timer_id_addr[i].base, (void *)(uintptr_t)(uint32_t)(g_timer_id_addr[i].base -
                        OFFSET_PADDR_TO_VADDR), PROT_READ | PROT_WRITE);
        if ((uintptr_t)ptr != (uint32_t)(g_timer_id_addr[i].base - OFFSET_PADDR_TO_VADDR)) {
            hm_error("ptr != timer addr[i].base \n");
            return -ENOMEM;
        }
        g_timer_id_addr[i].mapped = true;
        hm_debug(" ==> map paddr 0x%llx, size 0x%x\n", g_timer_id_addr[i].base, g_timer_id_addr[i].size);
    }
    return TMR_DRV_SUCCESS;
}

static uint32_t timer_address_unmap(void)
{
    uint32_t i;
    int32_t ret;

    for (i = 0; i < ARRAY_SIZE(g_timer_id_addr); i++) {
        if (!g_timer_id_addr[i].mapped)
            continue;

        ret = hm_io_unmap(g_timer_id_addr[i].base, (void *)(uintptr_t)g_timer_id_addr[i].base - OFFSET_PADDR_TO_VADDR);
        if (ret != TMR_DRV_SUCCESS) {
            hm_error("failed to unmap addr[%u] on init fail: err=0x%x\n", i, ret);
            return TMR_DRV_ERROR;
        } else {
            g_timer_id_addr[i].mapped = false;
        }
    }
    return TMR_DRV_SUCCESS;
}

int32_t timer_init(cref_t chnl_cref)
{
    uint32_t ret;
    int32_t drv_ret;

    drv_ret = timer_address_map();
    if (drv_ret != TMR_DRV_SUCCESS) {
        hm_error("timer IO address mapping failed\n");
        goto error_handler;
    }

    /* get irq capability, then we can use SRE_HwiXXX functions */
    drv_ret = hwi_init(chnl_cref);
    if (drv_ret != TMR_DRV_SUCCESS) {
        hm_error("hwi init failed\n");
        ret = TMR_DRV_ERROR;
        goto error_handler;
    }

    ret = timer_interrupt_init();
    if (ret != TMR_DRV_SUCCESS) {
        hm_error("interrupt failed\n");
        ret = TMR_DRV_ERROR;
        goto error_handler;
    }

    drv_ret = tc_drv_init();
    if (drv_ret != TMR_DRV_SUCCESS) {
        hm_error("drv failed\n");
        goto error_handler;
    }

    g_timer_tcb_cref = hmapi_tcb_cref();
    if (is_ref_err(g_timer_tcb_cref) != 0) {
        hm_error("get tcb cref failed\n");
        g_timer_tcb_cref = TMR_TCB_UNINITED;
        goto error_handler;
    }

    g_timer_inited = TMR_INITED;

    return TMR_DRV_SUCCESS;

error_handler:
    ret = timer_address_unmap();
    if (ret != TMR_DRV_SUCCESS)
        hm_error("timer IO address unmapping failed\n");

    return ret;
}

