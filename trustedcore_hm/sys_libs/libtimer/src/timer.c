/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Timer functions
 * Create: 2019-08-20
 */
#include "timer.h"
#include <securec.h>
#include <sys/usrsyscall_ext.h>
#include <hmlog.h>
#include <hm_unistd.h>
#include <ipclib.h>
#include <ac.h>
#include <ac_job.h>
#include <security_ops.h>
#ifndef CONFIG_OFF_DRV_TIMER
#include <timer_reg.h>
#endif
#include <time.h>
#include <timer_export.h>
#include <generic_timer.h>
#include <tee_inner_uuid.h>
#include <mem_ops_ext.h>
#include <hmdrv.h>
#include <limits.h>

static TEE_UUID g_drv_timer_uuid = TEE_DRV_TIMER;

#define TIME_OUT_NEVER (-1)
#define SHIFT_32       32U
#define US_PER_SECONDS 1000000
#define NS_PER_USEC    1000
#define US_PER_MSEC    1000
#define is_leap_year(year)  ((((year) % 4 == 0) && ((year) % 100 != 0)) || ((year) % 400 == 0))

#if (!defined CONFIG_TIMER_DISABLE) && (!defined CONFIG_OFF_DRV_TIMER)
static cref_t g_s_rslot;
#endif
static cref_t g_timer_tcb_cref;
static uint32_t g_tick_timer_fiq_num;
static struct ac_job g_ac_job;

static const uint32_t g_mon_lengths[][MONSPERYEAR] = {
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};
static const uint32_t g_year_lengths[] = { DAYSPERNYEAR, DAYSPERLYEAR };
#define leap_days_get(year) (((year) / 4) - ((year) / 100) + ((year) / 400))

cref_t timer_tcb_cref_get(void)
{
    return g_timer_tcb_cref;
}

uint32_t tick_timer_fiq_num_get(void)
{
    return g_tick_timer_fiq_num;
}

int renew_hmtimer_job_handler_internal(void)
{
    int ret;

    ret = ac_create_job(AC_SID_DRV_TIMER, TASKMAP2TASK_J, &g_ac_job.rref, &g_ac_job.cref);
    if (ret != TMR_OK) {
        hm_error("libhmdrv: create ac job error: %d\n", ret);
        return ret;
    }

    return TMR_OK;
}

int hm_timer_init_internal(void)
{
#if (defined CONFIG_TIMER_DISABLE) || (defined CONFIG_OFF_DRV_TIMER)
    hm_debug("timer is not support, please check\n");
    return 0;
#else
    int ret;
    if (g_s_rslot == 0) {
        ret = hm_ipc_get_ch_from_path(TIMER_PATH, &g_s_rslot);
        if (ret != TMR_OK) {
            hm_error("libtimer: get timer channel failed: %d\n", hm_getpid());
            return ret;
        }
    }

    g_tick_timer_fiq_num = TICK_TIMER_FIQ_NUMBLER;

    ret = ac_job_init(&g_ac_job, AC_SID_DRV_TIMER, TASKMAP2TASK_J);
    if (ret != TMR_OK) {
        hm_error("libhmdrv: create ac job error: %d\n", ret);
        return ret;
    }

    return TMR_OK;
#endif
}

#if (defined CONFIG_TIMER_DISABLE) || (defined CONFIG_OFF_DRV_TIMER)
uint32_t hmtimer_call(uint16_t id, uint64_t *args, int nr)
{
    (void)id;
    (void)args;
    (void)nr;

    return 0;
}
#else
static int timer_tcb_cref_init(struct timer_reply_msg_t rmsg)
{
    if (g_timer_tcb_cref == 0)
        g_timer_tcb_cref = rmsg.tcb_cref;

    if (g_timer_tcb_cref != rmsg.tcb_cref) {
        hm_error("timer tcb cref changed!\n");
        return TMR_ERR;
    }
    return TMR_OK;
}

static uint32_t hmtimer_msg_prepare(uint16_t id, const uint64_t *args, int nr, struct timer_req_msg_t *msg)
{
    if (g_s_rslot == 0) {
        hm_error("libtimer: forget to invoke init\n");
        return TMR_ERR;
    }

    if (nr > TIMER_MSG_NUM_MAX) {
        hm_error("libtimer: args size too large\n");
        return TMR_ERR;
    }

    msg->header.send.msg_class = HM_MSG_HEADER_CLASS_TMRMGR;
    msg->header.send.msg_flags = 0;
    msg->header.send.msg_id    = id;
    msg->header.send.msg_size  = sizeof(*msg);

    for (int32_t i = 0; i < nr; i++)
        msg->args[i] = args[i];

    /* enable ac_job before calling driver */
    msg->job_handler = g_ac_job.cref;

    return TMR_OK;
}

uint32_t hmtimer_call(uint16_t id, uint64_t *args, int nr)
{
    struct timer_req_msg_t msg    = { {{ 0 }}, { 0 }, 0 };
    struct timer_reply_msg_t rmsg = { {{ 0 }}, 0, { 0 } };

    if (nr < 0) {
        hm_error("invalid parameters, please check\n");
        return TMR_ERR;
    }

    /* return 4 register value at most */
    uint32_t rmsg_cnt = (uint32_t)((nr < TIMER_RMSG_MAX_NUM) ? nr : TIMER_RMSG_MAX_NUM);
    int ret;
    uint32_t msg_ret;

    if (args == NULL) {
        hm_error("invalid parameters, please check\n");
        return TMR_ERR;
    }

    msg_ret = hmtimer_msg_prepare(id, args, nr, &msg);
    if (msg_ret != TMR_OK) {
        hm_error("prepare failed 0x%x\n", msg_ret);
        return TMR_ERR;
    }

    ret = ac_job_enable(&g_ac_job);
    if (ret != TMR_OK) {
        hm_error("timer enable failed %d\n", ret);
        return TMR_ERR;
    }

    /* send timer msg to `drv_timer` */
    ret = hm_msg_call(g_s_rslot, &msg, sizeof(msg), &rmsg, sizeof(rmsg), 0, TIME_OUT_NEVER);
    if (ret != TMR_OK) {
        hm_error("msg: 0x%x failed: %d, swi_id: %u\n", (uint32_t)g_s_rslot, ret, id);
        (void)ac_job_disable(&g_ac_job);
        return TMR_ERR;
    }

    ret = timer_tcb_cref_init(rmsg);
    if (ret != TMR_OK) {
        hm_error("cref init failed\n");
        (void)ac_job_disable(&g_ac_job);
        return TMR_ERR;
    }

    /*
     * copy back the registers value returned by `drv_timer`, note `drv_timer` will return
     * 4 register value at most.
     */
    for (uint32_t i = 0; i < rmsg_cnt; i++)
        args[i] = rmsg.regs[i];

    ret = ac_job_disable(&g_ac_job);
    if (ret != TMR_OK) {
        hm_error("timer disable failed %d\n", ret);
        return TMR_ERR;
    }

    /* if TA has no permission to call drv timer, it will set rmsg.regs[0] to OS_ERROR */
    bool flag = (args[0] == OS_ERROR_A64) || ((uint32_t)args[0] == OS_ERROR);
    if (flag)
        return TMR_ERR;
    else
        return (LOWER_32_BITS(rmsg.header.reply.ret_val) == TMR_OK) ? TMR_OK : TMR_ERR;
}
#endif

#ifdef CONFIG_GENERIC_TIMER
uint64_t read_time_stamp(void)
{
    uint64_t timestamp;
    uint64_t cur_count;
    uint32_t sec;
    uint32_t nano_sec;
    uint32_t freq;

    cur_count = get_cntpct_el0();
    freq = get_cntfrq_el0();
    if (freq == 0)
        return TMR_OK; /* set timestamp value to 0 */

    sec = cur_count / freq;
    nano_sec = ((cur_count % freq) * NS_PER_SECONDS) / freq;
    timestamp = ((uint64_t)sec << SHIFT_32) + nano_sec;
    return timestamp;
}
#else
uint64_t read_time_stamp(void)
{
    uint64_t timestamp;
    uint32_t ret;
    uint64_t args[] = { 0, 0 };

    ret = hmtimer_call(SW_SYSCALL_TIMER_READSTAMP, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        hm_error("hm call failed %u\n", ret);
        return TMR_OK; /* set timestamp value to 0 */
    }

    timestamp = ((args[0] & 0xFFFFFFFF) | (args[1] << 32)); /* 32 bits */
    return timestamp;
}
#endif

uint32_t adjust_sys_time_internal(const struct tee_time_t *time)
{
#ifdef CONFIG_OFF_DRV_TIMER
    (void)time;
    return TMR_ERR;
#else
    if (time == NULL) {
        hm_error("time is NULL\n");
        return TMR_ERR;
    }

    uint64_t args[] = { (uint64_t)time->seconds, (uint64_t)time->millis };
    return hmtimer_call(SW_SYSCALL_ADJUST_SYS_TIME, args, ARRAY_SIZE(args));
#endif
}

void get_startup_time(struct tee_time_t *time, uint32_t *rtc_time)
{
    uint64_t args[] = { 0, 0, 0 };
    uint32_t ret;

    if ((time == NULL) || (rtc_time == NULL)) {
        hm_error("input params invalid\n");
        return;
    }

    ret = hmtimer_call(SW_SYSCALL_GET_STARTUP_TIME, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        time->seconds = 0;
        time->millis  = 0;
        *rtc_time     = 0;
        hm_error("hm timer call failed\n");
        return;
    }
    time->seconds = (int32_t)(args[0] & 0xFFFFFFFF); /* args[0]: seconds */
    time->millis = (int32_t)(args[1] & 0xFFFFFFFF); /* args[1]: millis */
    *rtc_time = (uint32_t)(args[2] & 0xFFFFFFFF); /* args[2]: time value */
}

void get_sys_rtc_time_kernel(struct tee_time_t *time)
{
    uint64_t args[] = { 0, 0 };
    uint32_t ret;

    if (time == NULL) {
        hm_error("input params invalid\n");
        return;
    }

    ret = hmtimer_call(SW_SYSCALL_GET_SYS_RTC_TIME_KERNEL, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        time->seconds = 0;
        time->millis  = 0;
        hm_error("hm timer call failed\n");
        return;
    }

    time->seconds = (int32_t)(args[0] & 0xFFFFFFFF); /* args[0]: seconds */
    time->millis = (int32_t)(args[1] & 0xFFFFFFFF); /* args[1]: millis */
}

void get_sys_rtc_time_offset(struct tee_time_t *time)
{
    uint64_t args[] = { 0, 0 };
    uint32_t ret;

    if (time == NULL) {
        hm_error("input params invalid\n");
        return;
    }

    ret = hmtimer_call(SW_SYSCALL_GET_SYS_RTC_TIME_OFFSET, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        time->seconds = 0;
        time->millis  = 0;
        hm_error("hm timer call failed\n");
        return;
    }

    time->seconds = (int32_t)(args[0] & 0xFFFFFFFF); /* args[0]: seconds */
    time->millis = (int32_t)(args[1] & 0xFFFFFFFF); /* args[1]: millis */
}

struct tm *hm_localtime_r(const time_t *restrict t, struct tm *restrict value)
{
    tee_date_time_kernel date_time;

    if ((value == NULL) || (t == NULL))
        return NULL;

    __gen_sys_date_time((uint32_t)*t, &date_time);

    /*
     * Shift tee_date_time_kernel to libc struct tm
     * tm_year: Year - 1900, that's why we minus 1900 here.
     * tm_mon: Month (0-11), that's why we minus 1 here.
     * tm_wday: Days of the week, has not implemented yet(could not get from date_time).
     * tm_yday: Days in the year, has not implemented yet(could not get from date_time).
     */
    if (date_time.year == 0 || date_time.month == 0) {
        hm_error("invalid parameters, please check\n");
        return NULL;
    }

    value->tm_year     = date_time.year - 1900; /* start year 1900 */
    value->tm_mon      = date_time.month - 1;
    value->tm_mday     = date_time.day;
    value->tm_hour     = date_time.hour;
    value->tm_min      = date_time.min;
    value->tm_sec      = date_time.seconds;
    value->tm_wday     = 0;
    value->tm_yday     = 0;
    value->tm_isdst    = 0;
    value->__tm_gmtoff = 0;
    value->__tm_zone   = NULL;

    return value;
}

static uint32_t increment_overflow(uint32_t *year, uint32_t carry)
{
    if (carry > (UINT_MAX - *year)) {
        hm_error("overflow, year=%u, carry=%u\n", *year, carry);
        return TMR_ERR;
    }

    *year += carry;

    return TMR_OK;
}

static uint32_t get_days_and_year(uint32_t *days, uint32_t *year)
{
    uint32_t ret;
    uint32_t new_year;
    uint32_t leap_days;
    uint32_t carry_over;

    while (*days >= g_year_lengths[is_leap_year(*year)]) {
        carry_over = *days / DAYSPERLYEAR;
        if (carry_over == 0)
            carry_over = 1;

        new_year = *year;
        ret = increment_overflow(&new_year, carry_over);
        if (ret != TMR_OK)
            return TMR_ERR;

        leap_days = leap_days_get(new_year - 1) - leap_days_get(*year - 1);
        if (new_year < *year)
            return TMR_ERR;
        *days -= (new_year - *year) * DAYSPERNYEAR;
        *days -= leap_days;
        *year = new_year;
    }

    return TMR_OK;
}

void gen_sys_date_time(const uint32_t rtc_time, struct tee_date_t *time)
{
    uint32_t seconds;
    uint32_t tdays;
    uint32_t idays;
    uint32_t rem_secs;
    uint32_t year;
    const uint32_t *ip = NULL;
    uint32_t ret;

    if (time == NULL) {
        hm_error("Error:time is null\n");
        return;
    }

    seconds = rtc_time;
    year = EPOCH_YEAR;
    tdays = seconds / SECSPERDAY;
    rem_secs = seconds - tdays * SECSPERDAY;

    ret = get_days_and_year(&tdays, &year);
    if (ret != TMR_OK) {
        hm_error("failed to get the day and year\n");
        return;
    }

    time->month = 0;
    idays = tdays;
    time->year = (int32_t)year;
    time->hour = (int32_t)(rem_secs / SECSPERHOUR);
    rem_secs %= SECSPERHOUR;
    time->min = (int32_t)(rem_secs / SECSPERMIN);
    time->seconds = (int32_t)(rem_secs % SECSPERMIN);
    ip = g_mon_lengths[is_leap_year(year)];

    for (int i = 0; i < MONSPERYEAR; i++) {
        time->month++;
        if (idays < ip[i])
            break;
        idays -= ip[i];
    }

    time->day = (int32_t)(idays + 1);
}

__attribute__((visibility("default"))) void gen_sys_date_time_internal(uint32_t secs,
                                                                       tee_date_time_kernel *date_time)
{
    if (date_time != NULL)
        gen_sys_date_time(secs, date_time);
}


#ifndef CONFIG_OFF_DRV_TIMER
void get_sys_date_time(tee_date_time_kernel *time_date)
{
    if (time_date == NULL) {
        hm_error("invalid parameters, please check\n");
        return;
    }

    uint32_t ret;

    tee_date_time_kernel *temp_time_date = tee_alloc_sharemem_aux(&g_drv_timer_uuid, sizeof(tee_date_time_kernel));
    if (temp_time_date == NULL) {
        hm_error("alloc date time sharemem failed\n");
        return;
    }

    (void)memcpy_s(temp_time_date, sizeof(tee_date_time_kernel), time_date, sizeof(tee_date_time_kernel));
    uint64_t args[] = { (uint64_t)(uintptr_t)temp_time_date };

    ret = hmtimer_call(SW_SYSCALL_GET_SYS_DATE_TIME, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        hm_error("hm timer call failed\n");
        goto out;
    }

    errno_t rc = memcpy_s(time_date, sizeof(tee_date_time_kernel), temp_time_date, sizeof(tee_date_time_kernel));
    if (rc != TMR_OK) {
        hm_error("copy temp time date failed\n");
        goto out;
    }
    (void)tee_free_sharemem(temp_time_date, sizeof(tee_date_time_kernel));
    return;
out:
    time_date->seconds = 0;
    time_date->millis  = 0;
    time_date->min     = 0;
    time_date->hour    = 0;
    time_date->day     = 0;
    time_date->month   = 0;
    time_date->year    = 0;
    (void)tee_free_sharemem(temp_time_date, sizeof(tee_date_time_kernel));
    return;
}
#else
void get_sys_date_time(tee_date_time_kernel *time_date)
{
    TEE_Time time;
    get_sys_rtc_time_internal(&time);
    if (time_date != NULL)
        gen_sys_date_time(time.seconds, time_date);
}
#endif

void get_sys_date_time_internal(tee_date_time_kernel *time_date)
{
    get_sys_date_time(time_date);
}
#ifdef CONFIG_OFF_DRV_TIMER
void delay_us(uint32_t microseconds)
{
    uint64_t counts = 0;
    uint64_t time_stamp;
    uint64_t start_time;
    uint64_t cur_time;

    if (microseconds > US_PER_SECONDS) {
        hm_error("The value of microseconds is extend the range\n");
        return;
    }

    time_stamp = read_time_stamp();
    while (counts < microseconds) {
        start_time = (uint64_t)UPPER_32_BITS(time_stamp) * US_PER_SECONDS + LOWER_32_BITS(time_stamp) / NS_PER_USEC;
        time_stamp = read_time_stamp();
        cur_time = (uint64_t)UPPER_32_BITS(time_stamp) * US_PER_SECONDS + LOWER_32_BITS(time_stamp) / NS_PER_USEC;
        counts += cur_time - start_time;
    }

    return;
}

uint32_t SRE_SwMsleep(uint32_t millisecond)
{
    delay_us(millisecond * US_PER_MSEC);
    return TMR_OK;
}

uint32_t SRE_SwUsleep(uint32_t microsecond)
{
    delay_us(microsecond);
    return TMR_OK;
}
#else
uint32_t SRE_SwMsleep(uint32_t millisecond)
{
    uint64_t counts = 0;
    uint64_t cycles;
    uint64_t cur;
    uint64_t end;
    uint64_t args[] = { 0 };
    uint32_t ret;

    if (millisecond > MS_PER_SECONDS) {
        hm_error("The value of millisecond is extend the range\n");
        return TMR_ERR;
    }

    cycles = (TIMER_CLK_FREQ / MS_PER_SECONDS + 1) * millisecond;
    ret    = hmtimer_call(SW_SYSCALL_READ_TIMER_COUNT, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        hm_error("get timer counter err\n");
        return ret;
    }

    end = args[0];
    while (counts < cycles) {
        ret = hmtimer_call(SW_SYSCALL_READ_TIMER_COUNT, args, ARRAY_SIZE(args));
        if (ret != TMR_OK) {
            hm_error("get timer counter err\n");
            return ret;
        }

        cur = args[0];
        if (cur == end)
            continue;
        else if (cur > end)
            counts += cur - end;
        else
            counts += TIMER_COUNT_MAX_32BIT - end + cur;
        end = cur;
    }

    return TMR_OK;
}

uint32_t SRE_SwUsleep(uint32_t microsecond)
{
    uint64_t counts = 0;
    uint64_t cycles;
    uint64_t cur;
    uint64_t end;
    uint64_t args[] = { 0 };
    uint32_t ret;

    if (microsecond > US_PER_SECONDS) {
        hm_error("The value of millisecond is extend the range\n");
        return TMR_ERR;
    }

    cycles = (TIMER_CLK_FREQ / US_PER_SECONDS + 1) * microsecond;
    ret    = hmtimer_call(SW_SYSCALL_READ_TIMER_COUNT, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        hm_error("get timer counter err\n");
        return ret;
    }

    end = args[0];
    while (counts < cycles) {
        ret = hmtimer_call(SW_SYSCALL_READ_TIMER_COUNT, args, ARRAY_SIZE(args));
        if (ret != TMR_OK) {
            hm_error("get timer counter err\n");
            return ret;
        }

        cur = args[0];
        if (cur == end) {
            continue;
        } else if (cur > end) {
            counts += cur - end;
        } else {
            counts += TIMER_COUNT_MAX_32BIT - end + cur;
        }
        end = cur;
    }

    return TMR_OK;
}
#endif
uint32_t timer_event_start_internal(const timer_event *t_event, const timeval_t *time)
{
    uint64_t args[] = { (uint64_t)(uintptr_t)t_event, (uint64_t)time->tval64 };
    return hmtimer_call(SW_SYSCALL_TIMER_START, args, ARRAY_SIZE(args));
}

uint32_t timer_event_stop_internal(const timer_event *t_event)
{
    uint64_t args[] = {
        (uint64_t)(uintptr_t)t_event,
    };
    return hmtimer_call(SW_SYSCALL_TIMER_STOP, args, ARRAY_SIZE(args));
}

uint64_t SRE_TimerGetExpire(timer_event *t_event)
{
#ifndef CONFIG_OFF_DRV_TIMER
    uint64_t timestamp;
    uint64_t args[] = { (uint64_t)(uintptr_t)t_event, 0, 0 };
    uint32_t ret;

    ret = hmtimer_call(SW_SYSCALL_GET_TIMER_EXPIRE, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        hm_error("hmtimer error\n");
        return TMR_ERR;
    }
    timestamp = (args[1] | (args[2] << 32)); /* 32bits */

    return timestamp;
#else
    if (t_event == NULL)
        return TMR_ERR;

    return t_event->expires.tval64;
#endif
}

uint32_t SRE_TimerCheck(timer_notify_data_kernel *timer_data)
{
#ifndef CONFIG_OFF_DRV_TIMER
    uint32_t ret;

    if (timer_data == NULL) {
        hm_error("invalid parameters, please check\n");
        return TMR_ERR;
    }

    timer_notify_data_kernel *temp_timer_data = tee_alloc_sharemem_aux(&g_drv_timer_uuid,
        sizeof(timer_notify_data_kernel));
    if (temp_timer_data == NULL) {
        hm_error("alloc temp timer data sharemem failed\n");
        return TMR_ERR;
    }
    (void)memcpy_s(temp_timer_data, sizeof(timer_notify_data_kernel), timer_data, sizeof(timer_notify_data_kernel));

    uint64_t args[] = {
        (uint64_t)(uintptr_t)temp_timer_data,
    };

    ret = hmtimer_call(SW_SYSCALL_CHECK_TIMER, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        hm_warn("timer check, hmtimer call error, ret = %u\n", ret);
        (void)tee_free_sharemem(temp_timer_data, sizeof(timer_notify_data_kernel));
        return TMR_ERR;
    }

    errno_t rc = memcpy_s(timer_data, sizeof(timer_notify_data_kernel),\
                          temp_timer_data, sizeof(timer_notify_data_kernel));
    if (rc != TMR_OK) {
        hm_error("timer check copy to timer data failed\n");
        (void)tee_free_sharemem(temp_timer_data, sizeof(timer_notify_data_kernel));
        return TMR_ERR;
    }

    (void)tee_free_sharemem(temp_timer_data, sizeof(timer_notify_data_kernel));
    return TMR_OK;
#else
    (void)timer_data;
    return TMR_OK;
#endif
}

#ifdef CONFIG_OFF_DRV_TIMER
uint32_t get_secure_rtc_time(void)
{
    uint64_t args[] = { 0 };

    return hm_drv_call(SW_SYSCALL_GET_RTC_TIME, args, ARRAY_SIZE(args));
}

void delay_ms(uint32_t millisecond)
{
    delay_us(millisecond * US_PER_MSEC);
}
#else
uint32_t get_secure_rtc_time(void)
{
    uint64_t args[] = { 0 };
    uint32_t ret;

    ret = hmtimer_call(SW_SYSCALL_GET_RTC_TIME, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        hm_error("get secure rtc time, hmtimer call error\n");
        return TIMER_INV_VALUE;
    }
    return (uint32_t)args[0];
}

void delay_ms(uint32_t delay)
{
    uint32_t ret;

    ret = SRE_SwMsleep(delay);
    if (ret != TMR_OK)
        hm_error("sleep failed!, delay = %u\n", delay);
}

void delay_us(uint32_t delay)
{
    uint32_t ret;
    /*
     * NOTE: in RTOSck, the timer freq is 32768 HZ, seems cannot handle `us` delay.
     * and the `SRE_DelayUs` code is exactly the same with `SRE_DelayMs`.
     * see `trusted_core/kernel/kernel/sys/sre_sys.c` for detail
     */
    ret = SRE_SwMsleep(delay);
    if (ret != TMR_OK)
        hm_error("sleep failed!, delay = %u\n", delay);
}
#endif
__attribute__((visibility("default"))) int set_ta_timer_permission_internal(const TEE_UUID *uuid,
                                                                            uint64_t permission)
{
    uint32_t ret;

    if (uuid == NULL) {
        hm_error("invalid parameters, please check\n");
        return TMR_ERR;
    }

    TEE_UUID *temp_uuid = tee_alloc_sharemem_aux(&g_drv_timer_uuid, sizeof(TEE_UUID));
    if (temp_uuid == NULL) {
        hm_error("alloc temp_uuid sharemem failed\n");
        return TMR_ERR;
    }
    (void)memcpy_s(temp_uuid, sizeof(TEE_UUID), uuid, sizeof(TEE_UUID));
    uint64_t args[] = {
        (uint64_t)(uintptr_t)temp_uuid,
        (uint64_t)permission
    };

    ret = hmtimer_call(SW_SYSCALL_SET_TIMER_PERMISSION, args, ARRAY_SIZE(args));
    if (ret != TMR_OK) {
        hm_error("set ta timer permission, hmtimer call error\n");
        (void)tee_free_sharemem(temp_uuid, sizeof(TEE_UUID));
        return TMR_ERR;
    }

    (void)tee_free_sharemem(temp_uuid, sizeof(TEE_UUID));
    return ret;
}

void syscall_timer_drv_init(void)
{
    uint32_t ret;
    uint64_t args[] = { 0 };

    ret = hmtimer_call(SW_SYSCALL_INIT_TIMER_DRV, args, ARRAY_SIZE(args));
    if (ret != TMR_OK)
        hm_error("timer get mix seed init failed\n");
}
