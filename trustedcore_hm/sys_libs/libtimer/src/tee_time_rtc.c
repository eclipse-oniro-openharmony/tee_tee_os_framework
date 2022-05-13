/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: rtc time api define in this file.
 * Create: 2022-04-22
 */
#include <sys_timer.h>
#include <hmlog.h>
#include <securec.h>
#include <tee_init.h>
#include <tee_mem_mgmt_api.h>
#include <sys_timer.h>
#include <tee_time_adapt.h>
#include <tee_rtc_adapt.h>
#include <tee_time_event.h>

#ifdef CONFIG_RTC_TIMER
timer_event *tee_rtc_time_event_create(sw_timer_event_handler handler, int32_t timer_class, void *priv_data)
{
    struct rtc_timer_ops_t *rtc_time_ops = NULL;
    rtc_time_ops = get_rtc_time_ops();
    if (rtc_time_ops == NULL)
        return NULL;

    return rtc_time_ops->rtc_time_event_create(handler, timer_class, priv_data);
}

uint32_t tee_rtc_time_event_start(timer_event *t_event, timeval_t *time)
{
    struct rtc_timer_ops_t *rtc_time_ops = NULL;
    rtc_time_ops = get_rtc_time_ops();
    if (rtc_time_ops == NULL)
        return TMR_ERR;

    return rtc_time_ops->rtc_time_event_start(t_event, time);
}

uint32_t tee_rtc_time_event_stop(timer_event *t_event)
{
    struct rtc_timer_ops_t *rtc_time_ops = NULL;
    rtc_time_ops = get_rtc_time_ops();
    if (rtc_time_ops == NULL)
        return TMR_ERR;

    return rtc_time_ops->rtc_time_event_stop(t_event);
}

uint32_t tee_rtc_time_event_check(timer_notify_data_kernel *timer_data)
{
    struct rtc_timer_ops_t *rtc_time_ops = NULL;
    rtc_time_ops = get_rtc_time_ops();
    if (rtc_time_ops == NULL)
        return TMR_ERR;

    return rtc_time_ops->rtc_time_event_check(timer_data);
}

uint64_t tee_rtc_time_event_get_remain(timer_event *t_event)
{
    struct rtc_timer_ops_t *rtc_time_ops = NULL;
    rtc_time_ops = get_rtc_time_ops();
    if (rtc_time_ops == NULL)
        return TMR_ERR;

    return rtc_time_ops->rtc_time_event_get_remain(t_event);
}

uint32_t tee_rtc_time_event_destroy(timer_event *t_event)
{
    struct rtc_timer_ops_t *rtc_time_ops = NULL;
    rtc_time_ops = get_rtc_time_ops();
    if (rtc_time_ops == NULL)
        return TMR_ERR;

    return rtc_time_ops->rtc_time_event_destroy(t_event);
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

    t_notify_data.property.type = timer_property->type;
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

    ret = tee_rtc_time_event_check(&t_notify_data);
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
        hm_error("malloc timer data failed\n");
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
        hm_error("current uuid is NULL\n");
        TEE_Free(timer_data);
        return TEE_ERROR_GENERIC;
    }
    safe_ret = memmove_s(&(timer_data->uuid), sizeof(timer_data->uuid), current_uuid, sizeof(timer_data->uuid));
    if (safe_ret != EOK) {
        hm_error("memmove fail, ret is 0x%x\n", safe_ret);
        TEE_Free(timer_data);
        return TEE_ERROR_GENERIC;
    }

    timer_data->session_id = get_current_session_id();
    if (timer_data->session_id == INVALID_SESSION_ID) {
        hm_error("get session id failed\n");
        TEE_Free(timer_data);
        return TEE_ERROR_GENERIC;
    }

    timer_data->type = timer_property->type;
    timer_data->expire_time = time_seconds;
    *timer = timer_data;
    return TEE_SUCCESS;
}


static TEE_Result timerevent_start(struct timer_event_private_data *timer_data)
{
    timer_event *t_event = NULL;
    timeval_t set_time;
    TEE_Result ret;

    t_event = tee_rtc_time_event_create(NULL, TIMER_RTC, timer_data);
    if (t_event == NULL) {
        hm_error("Failed to execute Create\n");
        return TEE_ERROR_TIMER_CREATE_FAILED;
    }

    set_time.tval.nsec = 0;
    set_time.tval.sec = (int32_t)timer_data->expire_time;
    ret = tee_rtc_time_event_start(t_event, &set_time);
    if (ret != TEE_SUCCESS) {
        hm_error("Failed to start timer event\n");
        (void)tee_rtc_time_event_destroy(t_event);
    }

    return ret;
}

static void timerevent_destroy(struct timer_event_private_data **timer)
{
    TEE_Free(*timer);
    *timer = NULL;
}

TEE_Result tee_ext_create_timer(uint32_t time_seconds, TEE_timer_property *timer_property)
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

static uint32_t get_timer_notify_data(timer_notify_data_kernel *timer_data, uint32_t type, uint32_t timer_class)
{
    uint32_t ret;
    errno_t safe_ret;

    timer_data->property.type        = type;
    timer_data->property.timer_class = timer_class;

    TEE_UUID *current_uuid = get_current_uuid();
    if (current_uuid == NULL) {
        hm_error("current uuid is NULL\n");
        return TMR_ERR;
    }
    safe_ret = memmove_s(&timer_data->uuid, sizeof(timer_data->uuid), current_uuid, sizeof(timer_data->uuid));
    if (safe_ret != EOK) {
        hm_error("error:sc_ret is 0x%x\n", safe_ret);
        return TMR_ERR;
    }

    ret = tee_rtc_time_event_check(timer_data);
    if (ret != TMR_OK) {
        hm_error("failed to find timer type is %u\n", type);
        return TMR_ERR;
    }

    return TMR_OK;
}

TEE_Result tee_ext_destory_timer(TEE_timer_property *timer_property)
{
    uint32_t ret;
    timer_notify_data_kernel t_notify_data;

    if (timer_property == NULL) {
        hm_error("invalid params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_timer_notify_data(&t_notify_data, timer_property->type, TIMER_RTC);
    if (ret != TMR_OK) {
        hm_error("get timer notify data failed, ret = %u\n", ret);
        return TEE_ERROR_TIMER_NOT_FOUND;
    }

    ret = tee_rtc_time_event_stop((timer_event *)(uintptr_t)(t_notify_data.property.handle));
    if (ret != TMR_OK)
        hm_error("stop timer failed: cannot find the timer, ret=0x%x\n", ret);

    ret = tee_rtc_time_event_destroy((timer_event *)(uintptr_t)(t_notify_data.property.handle));
    if (ret != TMR_OK) {
        hm_error("destroy timer failed: cannot find the timer, ret=0x%x\n", ret);
        return TEE_ERROR_TIMER_DESTORY_FAILED;
    }

    return TEE_SUCCESS;
}

TEE_Result tee_ext_get_timer_expire(TEE_timer_property *timer_property, uint32_t *time_seconds)
{
    uint32_t ret;
    timer_notify_data_kernel t_notify_data;

    if ((timer_property == NULL) || (time_seconds == NULL)) {
        hm_error("get timer expire: invalid params\n");
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

TEE_Result tee_ext_get_timer_remain(TEE_timer_property *timer_property, uint32_t *time_seconds)
{
    TEE_Result ret;
    timer_notify_data_kernel notify_data;

    if ((timer_property == NULL) || (time_seconds == NULL)) {
        hm_error("get timer remain: invalid params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_timer_notify_data(&notify_data, timer_property->type, TIMER_RTC);
    if (ret != TMR_OK) {
        hm_error("get timer notify data failed, ret = 0x%x\n", ret);
        return TEE_ERROR_TIMER_NOT_FOUND;
    }

    *time_seconds = (int64_t)tee_rtc_time_event_get_remain((timer_event *)(uintptr_t)(notify_data.property.handle));
    if (*time_seconds > INT32_MAX) {
        hm_error("get timer remain seconds error\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

uint32_t tee_get_secure_rtc_time(void)
{
    struct rtc_timer_ops_t *rtc_time_ops = NULL;
    rtc_time_ops = get_rtc_time_ops();
    if (rtc_time_ops == NULL)
        return TIMER_INV_VALUE;
    return rtc_time_ops->get_rtc_seconds();
}
#else
uint32_t tee_get_secure_rtc_time(void)
{
    return TIMER_INV_VALUE;
}

TEE_Result tee_ext_create_timer(uint32_t time_seconds, TEE_timer_property *timer_property)
{
    (void)time_seconds;
    (void)timer_property;
    return TMR_ERR;
}

TEE_Result tee_ext_destory_timer(const TEE_timer_property *timer_property)
{
    (void)timer_property;
    return TMR_ERR;
}

TEE_Result tee_ext_get_timer_expire(const TEE_timer_property *timer_property, uint32_t *time_seconds)
{
    (void)timer_property;
    (void)time_seconds;
    return TMR_ERR;
}

TEE_Result tee_ext_get_timer_remain(const TEE_timer_property *timer_property, uint32_t *time_seconds)
{
    (void)timer_property;
    (void)time_seconds;
    return TMR_ERR;
}
#endif