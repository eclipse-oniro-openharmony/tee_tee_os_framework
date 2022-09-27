/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2021. All rights reserved.
 * Create: 2021-01-20
 * Description: Reference of TEE time api definitions
 */

#ifndef __TEE_RTC_TIME_API_H
#define __TEE_RTC_TIME_API_H

/*
 * Create rtc timer event
 *
 * @param time_seconds   [IN] specified number of seconds
 * @param timer_property [IN] specified property of timer
 *
 * @return  TEE_SUCCESS success
 * @return  TEE_ERROR_GENERIC create timer fail
 */
TEE_Result TEE_EXT_CreateTimer(uint32_t time_seconds, TEE_timer_property *timer_property);

/*
 * Destory rtc timer event
 *
 * @param timer_property [IN] specified property of timer
 *
 * @return  TEE_SUCCESS success
 * @return  TEE_ERROR_GENERIC destroy timer fail
 */
TEE_Result TEE_EXT_DestoryTimer(TEE_timer_property *timer_property);

/*
 * Get expire time of rtc timer event
 *
 * @param timer_property [IN] specified property of timer
 * @param time_seconds   [OUT] expire time of rtc timer event
 *
 * @return  TEE_SUCCESS success
 * @return  TEE_ERROR_GENERIC get expire time fail
 */
TEE_Result TEE_EXT_GetTimerExpire(TEE_timer_property *timer_property, uint32_t *time_seconds);

/*
 * Get remain time of rtc timer event
 *
 * @param timer_property [IN] specified property of timer
 * @param time_seconds   [OUT] remain time of rtc timer event
 *
 * @return  TEE_SUCCESS success
 * @return  TEE_ERROR_GENERIC get remain time fail
 */
TEE_Result TEE_EXT_GetTimerRemain(TEE_timer_property *timer_property, uint32_t *time_seconds);

/*
 * Get secure rtc time
 *
 * @return current rtc seconds
 */
unsigned int __get_secure_rtc_time(void);
#endif
