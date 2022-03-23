/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Api function about time
 * Create: 2019-08-01
 */

#include "tee_time_api.h"

#include <securec.h>
#include <msg_ops.h>
#include <sre_typedef.h>
#include <tee_defines.h>
#include <hmlog.h>
#include <tee_mem_mgmt_api.h>
#include <ta_framework.h>
#include <tee_init.h>
#include <tee_trusted_storage_api.h>
#include <tee_misc.h>
#include <sre_rwroot.h>
#include <root_status_ops.h>
#include <lib_timer.h>
#ifdef CONFIG_LIB_TIMEMGR
#include <timemgr_api.h>
#endif
#include <api/errno.h>
#include <timer.h>
#include <generic_timer.h>
#include <hmdrv.h>

#define INVALID_SESSION_ID             0
#define PERSISTENT_TIME_BASE_FILE      "sec_storage/persistent_time"
#define TIMER_CREATE_SECONDS_THRESHOLD 2
#define POSITIVE_DIR                   1
#define NEGATIVE_DIR                   (-1)
#define SHIFT_32                       32U

static volatile uint32_t g_set_flag;
static timer_event *g_antiroot_event;

/* save offset between TA's persistent time and sys rtc time */
struct time_offset {
    int16_t dir;
    uint32_t offset;
    uint32_t base_sys_time;
};

struct timer_event_private_data {
    uint32_t dev_id;
    TEE_UUID uuid;
    uint32_t session_id;
    uint32_t type;
    uint32_t expire_time;
};

#ifdef CONFIG_OFF_DRV_TIMER
timer_event *rtc_timer_event_create(void *priv_data)
{
    uint32_t ret;
    uint64_t time_event;
    uint64_t args[] = {
        (uint64_t)(uintptr_t)&time_event,
        (uint64_t)(uintptr_t)priv_data
    };

    ret = hm_drv_call(SW_SYSCALL_TIMER_CREATE, args, ARRAY_SIZE(args));
    if (ret != TMR_OK)
        return NULL;

    return (timer_event *)(uintptr_t)time_event;
}

uint32_t rtc_timer_event_start(timer_event *t_event, timeval_t *time)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)t_event,
        (uint64_t)(uintptr_t)time
    };

    return hm_drv_call(SW_SYSCALL_TIMER_START, args, ARRAY_SIZE(args));
}

uint32_t rtc_timer_event_stop(timer_event *t_event)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)t_event,
    };

    return hm_drv_call(SW_SYSCALL_TIMER_STOP, args, ARRAY_SIZE(args));
}

uint32_t rtc_timer_event_destroy(timer_event *t_event)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)t_event,
    };

    return hm_drv_call(SW_SYSCALL_TIMER_DESTORY, args, ARRAY_SIZE(args));
}

uint64_t rtc_timer_event_get_expire(timer_event *t_event)
{
    uint64_t timestamp;
    uint64_t args[] = {
        (uint64_t)(uintptr_t)t_event,
        (uint64_t)(uintptr_t)&timestamp
    };
    uint32_t ret;

    ret = hm_drv_call(SW_SYSCALL_GET_TIMER_EXPIRE, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        hm_error("get expire fail\n");
        return TMR_ERR;
    }

    return timestamp;
}

uint32_t rtc_timer_event_check(timer_notify_data_kernel *timer_data)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)timer_data,
    };

    return hm_drv_call(SW_SYSCALL_CHECK_TIMER, args, ARRAY_SIZE(args));
}
#endif

#ifndef CONFIG_OFF_DRV_TIMER
static TEE_Result timer_event_start(uint32_t mill_second, struct timer_event_private_data *timer_data,
                                    timer_event **t_event)
{
    uint32_t ret;
    errno_t safe_ret;
    timeval_t set_time;

    if (timer_data == NULL) {
        hm_error("invalid param\n");
        return TEE_ERROR_GENERIC;
    }

    timer_data->dev_id = get_current_dev_id();
    if (timer_data->dev_id == INVALID_DEV_ID) {
        hm_error("timer event start: get current dev id failed\n");
        return TEE_ERROR_GENERIC;
    }

    TEE_UUID *current_uuid = get_current_uuid();
    if (current_uuid == NULL) {
        hm_error("current uuid is NULL!\n");
        return TEE_ERROR_GENERIC;
    }
    safe_ret = memmove_s(&(timer_data->uuid), sizeof(timer_data->uuid), current_uuid, sizeof(timer_data->uuid));
    if (safe_ret != EOK) {
        hm_error("memory move failed!\n");
        return TEE_ERROR_GENERIC;
    }

    timer_data->session_id = get_current_session_id();
    if (timer_data->session_id == INVALID_SESSION_ID) {
        hm_error("timer event start: get current session id failed\n");
        return TEE_ERROR_GENERIC;
    }

    *t_event = SRE_TimerEventCreate(NULL, TIMER_GENERIC, timer_data);
    if (*t_event == NULL) {
        hm_error("failed to create timer\n");
        return TEE_ERROR_TIMER_CREATE_FAILED;
    }

    set_time.tval.nsec = (mill_second % MS_PER_SECONDS) * NS_PER_MSEC;
    set_time.tval.sec  = mill_second / MS_PER_SECONDS;
    ret                = SRE_TimerEventStart(*t_event, &set_time);
    if (ret != TMR_OK) {
        hm_error("Failed to execute timer event start: ret=0x%x\n", ret);
        (void)SRE_TimerEventDestroy(*t_event);
        return TEE_ERROR_TIMER_CREATE_FAILED;
    }

    return TEE_SUCCESS;
}

static TEE_Result timer_msgsnd_to_globaltask(void)
{
    struct ta_to_global_msg send_msg  = {0};
    struct global_to_ta_msg entry_msg = {0};
    uint32_t ret;

    send_msg.ret             = TEE_PENDING;
    send_msg.agent_id        = 0;
    send_msg.session_context = NULL;

    ret = ipc_msg_snd(CALL_TA_DEFAULT_CMD, get_global_handle(), &send_msg, sizeof(send_msg));
    if (ret != TMR_OK) {
        hm_error("Failed to send msg, ret is 0x%x\n", ret);
        return TEE_ERROR_TIMER_CREATE_FAILED;
    }

    ret = ipc_msg_rcv_safe(OS_WAIT_FOREVER, NULL, &entry_msg, sizeof(entry_msg), get_global_handle());
    if (ret != TMR_OK)
        hm_error("Failed to receive msg, ret is 0x%x\n", ret); /* Need to go on */

    if (entry_msg.ret != TEE_SUCCESS)
        return entry_msg.ret;

    return TEE_SUCCESS;
}

TEE_Result tee_wait(uint32_t mill_second)
{
    TEE_Result ret;
    struct timer_event_private_data *timer_data = NULL;
    timer_event *t_event = NULL;

    if (mill_second == 0) {
        hm_debug("timer is set to 0, no need to wait, just return\n");
        return TEE_SUCCESS;
    }

    timer_data = TEE_Malloc(sizeof(*timer_data), 0);
    if (timer_data == NULL) {
        hm_error("timer event start: malloc timer data failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = timer_event_start(mill_second, timer_data, &t_event);
    if (ret != TEE_SUCCESS) {
        hm_error("timer event start failed!\n");
        TEE_Free(timer_data);
        return ret;
    }

    ret = timer_msgsnd_to_globaltask();
    if (ret != TEE_SUCCESS) {
        hm_error("send msg to global task failed!\n");
        (void)SRE_TimerEventStop(t_event);
        (void)SRE_TimerEventDestroy(t_event);
        TEE_Free(timer_data);
        return ret;
    }

    TEE_Free(timer_data);
    return TEE_SUCCESS;
}
#else
TEE_Result tee_wait(uint32_t mill_second)
{
    TEE_Result ret;
    cref_t timer_ref;

    timer_ref = hm_create_timer();
    if (is_ref_err(timer_ref))
        return ref_to_err(timer_ref);

    ret = hm_timer_start(timer_ref, mill_second);
    hm_delete_timer(timer_ref);
    return ret;
}
#endif
/*
 * get pointer to TEE_Time
 * assign it from ReadTimestamp
 * it will get the system time via time
 */
void tee_get_system_time(TEE_Time *time)
{
    uint64_t time_value;

    if (time == NULL) {
        hm_error("invalid input, null pointer\n");
        return;
    }

    time_value = SRE_ReadTimestamp();
    if (time_value == 0) {
        hm_error("time value is zero\n");
        return;
    }

    time->seconds = UPPER_32_BITS(time_value); /* 32bits: time high */
    time->millis  = LOWER_32_BITS(time_value) / NS_PER_MSEC;
}

#ifdef CONFIG_GENERIC_TIMER
static struct tee_time_t g_rtc_offset;
void get_sys_rtc_time_internal(TEE_Time *time)
{
    TEE_Time cur_time;

    if (time == NULL) {
        hm_error("invalid input\n");
        return;
    }

#ifndef CONFIG_OFF_DRV_TIMER
    if (g_rtc_offset.seconds == 0)
        get_sys_rtc_time_offset(&g_rtc_offset);
#else
    if (g_rtc_offset.seconds == 0)
        hm_timer_get_offset(&g_rtc_offset.seconds, &g_rtc_offset.millis);
#endif

    tee_get_system_time(&cur_time);

    if (cur_time.millis + g_rtc_offset.millis > MS_PER_SECONDS) {
        cur_time.seconds += (g_rtc_offset.seconds + 1);
        cur_time.millis += (g_rtc_offset.millis - MS_PER_SECONDS);
    } else {
        cur_time.seconds += g_rtc_offset.seconds;
        cur_time.millis += g_rtc_offset.millis;
    }

    time->seconds = (uint32_t)cur_time.seconds;
    time->millis  = (uint32_t)cur_time.millis;
}
#else
static TEE_Time g_sys_startup_time;
/*
 * get system rtc time to pointer time
 * it different from get system time
 */
void get_sys_rtc_time_internal(TEE_Time *time)
{
    struct tee_time_t tmp_time;

    if (time == NULL) {
        hm_error("invalid input\n");
        return;
    }

    get_sys_rtc_time_kernel(&tmp_time);
    /* Actually tmp_time is always larger than g_sys_startup_time */
    if (tmp_time.millis < (int32_t)g_sys_startup_time.millis) {
        tmp_time.millis += (int32_t)(MS_PER_SECONDS - g_sys_startup_time.millis);
        tmp_time.seconds -= (int32_t)(1 + g_sys_startup_time.seconds);
    } else {
        tmp_time.seconds -= (int32_t)g_sys_startup_time.seconds;
        tmp_time.millis -= (int32_t)g_sys_startup_time.millis;
    }

    time->seconds = (uint32_t)tmp_time.seconds;
    time->millis  = (uint32_t)tmp_time.millis;
}
#endif

static uint32_t get_rtc_seconds(void)
{
#ifdef CONFIG_RTC_TIMER
    return get_secure_rtc_time();
#else
    TEE_Time time = {0};
    get_sys_rtc_time(&time);
    return time.seconds;
#endif
}

static TEE_Result persistent_time_check(TEE_Time *time, const struct time_offset *offset_val)
{
    uint32_t seconds;

    seconds = get_rtc_seconds();
    if (seconds == TIMER_INV_VALUE) {
        hm_error("Failed to get rtc time\n");
        return TEE_ERROR_TIME_NEEDS_RESET;
    }

    if (seconds < offset_val->base_sys_time) {
        hm_error("Time rollback\n");
        return TEE_ERROR_TIME_NEEDS_RESET;
    }

    /*
     * millis is always 0, because rtc accuracy is 1s.
     * Depends on GP spec, even if time overflow we should return the actually time.
     */
    time->millis = 0;
    if (offset_val->dir == NEGATIVE_DIR) {
        time->seconds = seconds - offset_val->offset;
        if (time->seconds > seconds) {
            hm_error("persistent time overflow\n");
            return TEE_ERROR_OVERFLOW;
        }
    } else {
        time->seconds = seconds + offset_val->offset;
        if (time->seconds < seconds) {
            hm_error("persistent time overflow\n");
            return TEE_ERROR_OVERFLOW;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result get_ta_persistent_time(TEE_Time *time)
{
    struct time_offset offset_val = { 0 };
    TEE_ObjectHandle object       = NULL;
    uint32_t count                = 0;
    TEE_Result ret;

    if (time == NULL) {
        hm_error("invalid input\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /*
     *  For an error different
     *  from TEE_ERROR_OVERFLOW, this placeholder is filled with zeros.
     */
    time->seconds = 0;
    time->millis  = 0;
    ret           = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, PERSISTENT_TIME_BASE_FILE,
                                             strlen(PERSISTENT_TIME_BASE_FILE), TEE_DATA_FLAG_ACCESS_READ, &object);
    if (ret != TEE_SUCCESS) {
        hm_error("Failed to open persistent object\n");
        return TEE_ERROR_TIME_NOT_SET;
    }

    ret = TEE_ReadObjectData(object, &offset_val, sizeof(offset_val), &count);
    TEE_CloseObject(object);
    if ((ret != TEE_SUCCESS) || (count != sizeof(offset_val))) {
        hm_error("read failed\n");
        return TEE_ERROR_TIME_NOT_SET;
    }

    ret = persistent_time_check(time, &offset_val);
    if (ret != TEE_SUCCESS) {
        hm_error("Failed to check\n");
        return ret;
    }

    return TEE_SUCCESS;
}

TEE_Result set_ta_persistent_time(TEE_Time *time)
{
    struct time_offset offset_val = { 0 };
    uint32_t seconds;
    TEE_Result ret;
    TEE_ObjectHandle object = NULL;

    if (time == NULL) {
        hm_error("invalid input\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /*
     * Get sys time from RTC:always increase even if power off.
     * Use TEE_SetTAPersistentTime and TEE_GetTAPersistentTime
     * to get the true time that has past. A typical usecase in DRM.
     */
    seconds = get_rtc_seconds();
    if (seconds == TIMER_INV_VALUE) {
        hm_error("Failed to get rtc time\n");
        return TEE_ERROR_TIME_NEEDS_RESET;
    }

    offset_val.base_sys_time = seconds;
    if (time->seconds >= seconds) {
        offset_val.dir    = POSITIVE_DIR;
        offset_val.offset = time->seconds - seconds;
    } else {
        offset_val.dir    = NEGATIVE_DIR;
        offset_val.offset = seconds - time->seconds;
    }

    ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, PERSISTENT_TIME_BASE_FILE,
                                     strlen(PERSISTENT_TIME_BASE_FILE), TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL,
                                     &offset_val, sizeof(offset_val), &object);
    if (ret != TEE_SUCCESS) {
        hm_error("set TA persistent time error: ret is 0x%x\n", ret);
        return ret;
    }

    TEE_CloseObject(object);

    return ret;
}

__attribute__((visibility("default"))) void get_ree_time(TEE_Time *time)
{
    int32_t ret;

    if (time == NULL) {
        hm_error("invalid input\n");
        return;
    }

    ret = get_time_of_data(&time->seconds, &time->millis, NULL, 0);
    if (ret != TMR_OK) {
        hm_error("get time of data failed!\n");
        return;
    }
}

void get_ree_time_str(char *time_str, uint32_t time_str_len)
{
    int32_t ret;

    if ((time_str == NULL) || (time_str_len == 0)) {
        hm_error("invalid input, please check\n");
        return;
    }

    ret = get_time_of_data(NULL, NULL, time_str, time_str_len);
    if (ret != TMR_OK)
        hm_error("get time of data failed!\n");
}

static TEE_Result start_timer_event(timer_event *t_event, timeval_t *time)
{
    uint32_t ret;

    ret = SRE_TimerEventStart(t_event, time);
    if (ret != TMR_OK) {
        hm_error("Failed to execute Start, ret: %u\n", ret);
        return TEE_ERROR_TIMER_CREATE_FAILED;
    }

    hm_info("Start Timer Event Success\n");

    return TEE_SUCCESS;
}

#ifdef CONFIG_OFF_DRV_TIMER
static TEE_Result rtc_start_timer_event(timer_event *t_event, timeval_t *time)
{
    uint32_t ret;

    ret = rtc_timer_event_start(t_event, time);
    if (ret != TMR_OK) {
        hm_error("Failed to execute Start, ret: %u\n", ret);
        return TEE_ERROR_TIMER_CREATE_FAILED;
    }

    hm_info("Start Timer Event Success\n");

    return TEE_SUCCESS;
}
#endif

static uint32_t get_timer_notify_data(timer_notify_data_kernel *timer_data, uint32_t type, uint32_t timer_class)
{
    uint32_t ret;
    errno_t safe_ret;

    timer_data->property.type        = type;
    timer_data->property.timer_class = timer_class;

    TEE_UUID *current_uuid = get_current_uuid();
    if (current_uuid == NULL) {
        hm_error("current uuid is NULL!\n");
        return TMR_ERR;
    }
    safe_ret = memmove_s(&timer_data->uuid, sizeof(timer_data->uuid), current_uuid, sizeof(timer_data->uuid));
    if (safe_ret != EOK) {
        hm_error("error:sc_ret is 0x%x\n", safe_ret);
        return TMR_ERR;
    }

#ifdef CONFIG_OFF_DRV_TIMER
    ret = rtc_timer_event_check(timer_data);
#else
    ret = SRE_TimerCheck(timer_data);
#endif
    if (ret != TMR_OK) {
        hm_error("failed to find timer type is %u\n", type);
        return TMR_ERR;
    }

    return TMR_OK;
}

static TEE_Result timer_create_param_check(uint32_t time_seconds, const TEE_timer_property *timer_property)
{
    timer_notify_data_kernel t_notify_data = { 0 };
    uint32_t ret;
    errno_t safe_ret;

    if (time_seconds <= TIMER_CREATE_SECONDS_THRESHOLD) { /* not be less equal to 2s */
        hm_error("time_seconds should not be less equal to timer %u\n", time_seconds);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (timer_property == NULL) {
        hm_error("timer create param check: property is NULL\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    t_notify_data.property.type        = timer_property->type;
    t_notify_data.property.timer_class = TIMER_RTC;
    TEE_UUID *current_uuid = get_current_uuid();
    if (current_uuid == NULL) {
        hm_error("current uuid is NULL!\n");
        return TEE_ERROR_GENERIC;
    }
    safe_ret =
        memmove_s(&t_notify_data.uuid, sizeof(t_notify_data.uuid), current_uuid, sizeof(t_notify_data.uuid));
    if (safe_ret != EOK) {
        hm_error("memmove_s error:ret is 0x%x\n", safe_ret);
        return TEE_ERROR_GENERIC;
    }

#ifdef CONFIG_OFF_DRV_TIMER
    ret = rtc_timer_event_check(&t_notify_data);
#else
    ret = SRE_TimerCheck(&t_notify_data);
#endif
    if (ret == TMR_OK) {
        hm_error("Timer is exist, no longer need to create timer event\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result timerevent_create(uint32_t time_seconds, const TEE_timer_property *timer_property,
                                    struct timer_event_private_data **timer)
{
    struct timer_event_private_data *timer_data = NULL;
    errno_t safe_ret;

    timer_data = TEE_Malloc(sizeof(*timer_data), 0);
    if (timer_data == NULL) {
        hm_error("malloc timer data failed!\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    timer_data->dev_id = get_current_dev_id();
    if (timer_data->dev_id == INVALID_DEV_ID) {
        hm_error("Failed to get device id\n");
        TEE_Free(timer_data);
        return TEE_ERROR_GENERIC;
    }

    TEE_UUID *current_uuid = get_current_uuid();
    if (current_uuid == NULL) {
        hm_error("current uuid is NULL!\n");
        TEE_Free(timer_data);
        return TEE_ERROR_GENERIC;
    }
    safe_ret = memmove_s(&(timer_data->uuid), sizeof(timer_data->uuid), current_uuid, sizeof(timer_data->uuid));
    if (safe_ret != EOK) {
        hm_error("error:sc_ret is 0x%x\n", safe_ret);
        TEE_Free(timer_data);
        return TEE_ERROR_GENERIC;
    }

    timer_data->session_id = get_current_session_id();
    if (timer_data->session_id == INVALID_SESSION_ID) {
        hm_error("get session id failed\n");
        TEE_Free(timer_data);
        return TEE_ERROR_GENERIC;
    }

    timer_data->type        = timer_property->type;
    timer_data->expire_time = time_seconds;
    *timer                  = timer_data;

    return TEE_SUCCESS;
}

static void timerevent_destroy(struct timer_event_private_data **timer)
{
    TEE_Free(*timer);
    *timer = NULL;
}

static TEE_Result timerevent_start(struct timer_event_private_data *timer_data)
{
    timer_event *t_event = NULL;
    timeval_t set_time;
    TEE_Result ret;

#ifdef CONFIG_OFF_DRV_TIMER
    t_event = rtc_timer_event_create(timer_data);
#else
     t_event = SRE_TimerEventCreate(NULL, TIMER_RTC, timer_data);
#endif
    if (t_event == NULL) {
        hm_error("Failed to execute Create\n");
        return TEE_ERROR_TIMER_CREATE_FAILED;
    }

    set_time.tval.nsec = 0;
    set_time.tval.sec  = timer_data->expire_time;
#ifdef CONFIG_OFF_DRV_TIMER
    ret = rtc_start_timer_event(t_event, &set_time);
#else
    ret = start_timer_event(t_event, &set_time);
#endif
    if (ret != TEE_SUCCESS) {
        hm_error("Failed to start timer event!\n");
#ifdef CONFIG_OFF_DRV_TIMER
        (void)rtc_timer_event_destroy(t_event);
#else
        (void)SRE_TimerEventDestroy(t_event);
#endif
    }

    return ret;
}

TEE_Result tee_ext_create_timer(uint32_t time_seconds, const TEE_timer_property *timer_property)
{
    struct timer_event_private_data *timer_data = NULL;
    uint32_t ret;

    if (timer_property == NULL) {
        hm_error("Create Timer: property is NULL\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = timer_create_param_check(time_seconds, timer_property);
    if (ret != TEE_SUCCESS) {
        hm_error("Create Timer: check failed\n");
        return ret;
    }

    ret = timerevent_create(time_seconds, timer_property, &timer_data);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = timerevent_start(timer_data);
    if (ret != TEE_SUCCESS) {
        timerevent_destroy(&timer_data);
        return ret;
    }

    timerevent_destroy(&timer_data);

    return TEE_SUCCESS;
}

TEE_Result tee_ext_destory_timer(const TEE_timer_property *timer_property)
{
    uint32_t ret;
    timer_notify_data_kernel t_notify_data;

    if (timer_property == NULL) {
        hm_error("invalid params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_timer_notify_data(&t_notify_data, timer_property->type, TIMER_RTC);
    if (ret != TMR_OK) {
        hm_error("get timer notify data failed ! ret = %u\n", ret);
        return TEE_ERROR_TIMER_NOT_FOUND;
    }

#ifdef CONFIG_OFF_DRV_TIMER
    ret = rtc_timer_event_stop((timer_event *)(uintptr_t)(t_notify_data.property.handle));
#else
    ret = SRE_TimerEventStop((timer_event *)(uintptr_t)(t_notify_data.property.handle));
#endif
    if (ret != TMR_OK)
        hm_error("stop timer failed: cannot find the timer, ret=0x%x\n", ret);

#ifdef CONFIG_OFF_DRV_TIMER
    ret = rtc_timer_event_destroy((timer_event *)(uintptr_t)(t_notify_data.property.handle));
#else
    ret = SRE_TimerEventDestroy((timer_event *)(uintptr_t)(t_notify_data.property.handle));
#endif
    if (ret != TMR_OK) {
        hm_error("destroy timer failed: cannot find the timer, ret=0x%x\n", ret);
        return TEE_ERROR_TIMER_DESTORY_FAILED;
    }

    return TEE_SUCCESS;
}

TEE_Result tee_ext_get_timer_expire(const TEE_timer_property *timer_property, uint32_t *time_seconds)
{
    uint32_t ret;
    timer_notify_data_kernel t_notify_data;

    if ((timer_property == NULL) || (time_seconds == NULL)) {
        hm_error("get timer expire: invalid params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_timer_notify_data(&t_notify_data, timer_property->type, TIMER_RTC);
    if (ret != TMR_OK) {
        hm_error("get timer notify data failed, ret = %u\n", ret);
        return TEE_ERROR_TIMER_NOT_FOUND;
    }

    *time_seconds = t_notify_data.expire_time;

    return TEE_SUCCESS;
}

#ifndef CONFIG_OFF_DRV_TIMER
static uint64_t tee_get_time_stamp(void)
{
    uint64_t timestamp;
    uint32_t ret;
    uint64_t args[] = { 0, 0 };

    ret = hmtimer_call(SW_SYSCALL_TIMER_READSTAMP, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        hm_error("hm call failed %u\n", ret);
        return TMR_OK; /* set timestamp value to 0 */
    }

    timestamp = ((args[0] & 0xFFFFFFFF) | (args[1] << SHIFT_32));
    return timestamp;
}

TEE_Result tee_ext_get_timer_remain(const TEE_timer_property *timer_property, uint32_t *time_seconds)
{
    TEE_Result ret;
    timeval_t time_u64;
    timeval_t time_cur_u64;
    timer_notify_data_kernel t_notify_data;

    if ((timer_property == NULL) || (time_seconds == NULL)) {
        hm_error("get timer remain: invalid params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_timer_notify_data(&t_notify_data, timer_property->type, TIMER_RTC);
    if (ret != TMR_OK) {
        hm_error("get timer notify data failed, ret = 0x%x\n", ret);
        return TEE_ERROR_TIMER_NOT_FOUND;
    }

    time_cur_u64.tval64 = (int64_t)tee_get_time_stamp();
    if (time_cur_u64.tval64 <= 0) {
        hm_error("get current time failed\n");
        return TEE_ERROR_GENERIC;
    }

    time_u64.tval64 = (int64_t)SRE_TimerGetExpire((timer_event *)(uintptr_t)(t_notify_data.property.handle));
    if ((time_u64.tval.sec <= 0) || (time_u64.tval.sec < time_cur_u64.tval.sec)) {
        hm_error("get timer remain seconds error\n");
        return TEE_ERROR_GENERIC;
    }

    time_u64.tval64 = time_u64.tval64 - time_cur_u64.tval64;
    if (time_u64.tval.nsec < 0)
        time_u64.tval.nsec += NS_PER_SECONDS;
    *time_seconds = time_u64.tval.sec;

    return TEE_SUCCESS;
}
#else
TEE_Result tee_ext_get_timer_remain(const TEE_timer_property *timer_property, uint32_t *time_seconds)
{
    timeval_t time_u64;
    uint32_t cur_time;
    TEE_Result ret;
    timer_notify_data_kernel t_notify_data;

    if ((timer_property == NULL) || (time_seconds == NULL)) {
        hm_error("get timer remain: invalid params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_timer_notify_data(&t_notify_data, timer_property->type, TIMER_RTC);
    if (ret != TMR_OK) {
        hm_error("get timer notify data failed, ret = 0x%x\n", ret);
        return TEE_ERROR_TIMER_NOT_FOUND;
    }

    cur_time = get_secure_rtc_time();

    time_u64.tval64 = (int64_t)rtc_timer_event_get_expire((timer_event *)(uintptr_t)(t_notify_data.property.handle));
    if ((time_u64.tval.sec <= 0) || ((uint32_t)time_u64.tval.sec < cur_time)) {
        hm_error("get timer remain seconds error!\n");
        return TEE_ERROR_GENERIC;
    }

    *time_seconds = time_u64.tval.sec - cur_time;
    return TEE_SUCCESS;
}
#endif

static void lib_tee_anti_root_handler(void *priv_data)
{
    int32_t ret;

    /*
     * The needs the handler has a 'void *' parameter.
     * So we should keep priv_data for compatible with other functions.
     */
    (void)priv_data;

    if (g_set_flag == 0) {
        uint32_t status = ((uint32_t)0x1 << ITIMEOUTBIT);
        ret             = __SRE_WriteRootStatus(status);
        if (ret != TMR_OK)
            hm_error("antiroot: write root status error\n");
        else
            g_set_flag = 1;
    }
}

__attribute__((visibility("default"))) \
TEE_Result tee_antiroot_create_timer(uint32_t time_seconds)
{
    timeval_t set_time;
    int32_t timer_data = 0;
    uint32_t ret;
    timer_event *t_event = NULL;

    if (time_seconds <= TIMER_CREATE_SECONDS_THRESHOLD) {
        hm_error("timer is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (g_antiroot_event != NULL) {
        hm_error("timer type already exist\n");
        return TEE_ERROR_BAD_STATE;
    }

    if (g_set_flag != 0) {
        hm_error("stop creat antitimer, only work once because of\n");
        return TEE_SUCCESS;
    }

    t_event = SRE_TimerEventCreate((sw_timer_event_handler)(lib_tee_anti_root_handler), TIMER_CLASSIC, &timer_data);
    if (t_event == NULL) {
        hm_error("Failed to execute TimerEventCreate\n");
        return TEE_ERROR_TIMER_CREATE_FAILED;
    }

    g_antiroot_event   = t_event;
    set_time.tval.nsec = 0;
    set_time.tval.sec  = time_seconds;
    ret                = start_timer_event(t_event, &set_time);
    if (ret != TEE_SUCCESS) {
        (void)SRE_TimerEventDestroy(t_event);
        hm_error("start timer event failed!\n");
        return TEE_ERROR_TIMER;
    }

    return TEE_SUCCESS;
}

__attribute__((visibility("default"))) \
TEE_Result tee_antiroot_destory_timer(void)
{
    uint32_t ret;

    if ((g_antiroot_event == NULL) && (g_set_flag == 1))
        return TEE_SUCCESS;

    if (g_antiroot_event == NULL) {
        hm_error("antiroot timer has been destory\n");
        return TEE_ERROR_TIMER;
    }

    /* stop timer may fail when timeout, no need to return */
    ret = SRE_TimerEventStop(g_antiroot_event);
    if (ret != TMR_OK)
        hm_warn("stop timer failed: cannot find the timer, ret=0x%x\n", ret);

    ret = SRE_TimerEventDestroy(g_antiroot_event);
    if (ret != TMR_OK) {
        hm_error("destroy timer failed: cannot find the timer, ret=0x%x\n", ret);
        return TEE_ERROR_TIMER_DESTORY_FAILED;
    }

    g_antiroot_event = NULL;

    return TEE_SUCCESS;
}
