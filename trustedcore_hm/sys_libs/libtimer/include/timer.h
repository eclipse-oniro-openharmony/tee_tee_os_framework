/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header of timer
 * Create: 2019-08-20
 */

#ifndef SYS_LIBS_LIBTIMER_A32_TIMER_H
#define SYS_LIBS_LIBTIMER_A32_TIMER_H

#include <stdint.h>
#include <kernel/time.h>
#include <hm_msg_type.h>
#include <sre_syscalls_id.h>
#include <tee_time_api.h>
#include <sys_timer.h>
#include <time.h>

#define TIMER_PATH                   "hmtimer"
#define TIMER_MSG_NUM_MAX            16
#define TIMER_RMSG_MAX_NUM           4
#define TIMER_MASK                   0xFFFFFFFF

#define TMR_OK  0
#define TMR_ERR 1

#define TIMER_INV_VALUE 0

struct timer_req_msg_t {
    hm_msg_header header;
    uint64_t args[TIMER_MSG_NUM_MAX];
    cref_t job_handler;
} __attribute__((__packed__));

struct timer_reply_msg_t {
    hm_msg_header header;
    cref_t tcb_cref;
    uint64_t regs[TIMER_RMSG_MAX_NUM]; /* 4 params */
} __attribute__((__packed__));

#define TIMER_REQ_MSG_SIZE (sizeof(struct timer_req_msg_t))
#define TIMER_REP_MSG_SIZE (sizeof(struct timer_reply_msg_t))

int hm_timer_init(void);
int renew_hmtimer_job_handler_internal(void);
struct tm *hm_localtime_r(const time_t *restrict t, struct tm *restrict tm);
struct tm *__localtime_r(const time_t *restrict, struct tm *restrict);
uint32_t hmtimer_call(uint16_t id, uint64_t *args, int nr);
int nanosleep(const struct timespec *req, struct timespec *rem);
cref_t timer_tcb_cref_get(void);
uint32_t tick_timer_fiq_num_get(void);
void get_sys_rtc_time_kernel(tee_time_kernel *time);
void get_sys_rtc_time_offset(tee_time_kernel *time);
uint32_t get_secure_rtc_time(void);

uint32_t SRE_SwMsleep(uint32_t millisecond);
uint32_t SRE_SwUsleep(uint32_t microsecond);
uint32_t SRE_TimerEventStop(timer_event *t_event);
uint32_t SRE_TimerEventDestroy(timer_event *t_event);
uint32_t SRE_TimerCheck(timer_notify_data_kernel *timer_data);

void get_startup_time(tee_time_kernel *time, uint32_t *rtc_time);
uint32_t get_secure_rtc_time(void);
void syscall_timer_drv_init(void);

void init_startup_time_kernel_internal(uint32_t rtc_time);
uint32_t adjust_sys_time_internal(const struct tee_time_t *time);
int hm_timer_init_internal(void);
void tee_get_system_time(TEE_Time *time);
unsigned int sleep_internal(unsigned int seconds);
int nanosleep_internal(const struct timespec *req, struct timespec *rem);
struct tm *localtime_internal(const time_t *t);
TEE_Result tee_wait(uint32_t mill_second);
TEE_Result get_ta_persistent_time(TEE_Time *time);
TEE_Result set_ta_persistent_time(TEE_Time *time);
void get_ree_time(TEE_Time *time);
void get_ree_time_str(char *time_str, uint32_t time_str_len);
TEE_Result tee_ext_create_timer(uint32_t time_seconds, const TEE_timer_property *timer_property);
TEE_Result tee_ext_destory_timer(const TEE_timer_property *timer_property);
TEE_Result tee_ext_get_timer_expire(const TEE_timer_property *timer_property, uint32_t *time_seconds);
TEE_Result tee_ext_get_timer_remain(const TEE_timer_property *timer_property, uint32_t *time_seconds);
TEE_Result tee_antiroot_create_timer(uint32_t time_seconds);
TEE_Result tee_antiroot_destory_timer(void);
void get_sys_rtc_time_internal(TEE_Time *time);
void gen_sys_date_time_internal(uint32_t secs, tee_date_time_kernel *date_time);
void get_sys_date_time_internal(tee_date_time_kernel *time_date);
timer_event *timer_event_create_internal(sw_timer_event_handler handler, int32_t timer_class, void *priv_data);
UINT32 timer_event_destroy_internal(const timer_event *t_event);
UINT32 timer_event_start_internal(const timer_event *t_event, const timeval_t *time);
UINT32 timer_event_stop_internal(const timer_event *t_event);
void delay_ms(uint32_t delay);
void delay_us(uint32_t delay);
uint64_t read_time_stamp(void);
int set_ta_timer_permission_internal(const TEE_UUID *uuid, uint64_t permission);
void release_timer_event_internal(const TEE_UUID *uuid);

timer_event *tee_timer_event_create(sw_timer_event_handler handler, int32_t timer_class, void *priv_data);
UINT32 tee_timer_event_destroy(timer_event *t_event);
UINT32 tee_timer_event_start(timer_event *t_event, timeval_t *time);
UINT32 tee_timer_event_stop(timer_event *t_event);
#endif /* SYS_LIBS_LIBTIMER_A32_TIMER_H */
