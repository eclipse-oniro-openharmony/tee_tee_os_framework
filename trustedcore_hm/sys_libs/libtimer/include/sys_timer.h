/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, timer function
 * Create: 2019-12-10
 */
#ifndef LIBTIMER_A32_SYS_TIMER_H
#define LIBTIMER_A32_SYS_TIMER_H

#include <dlist.h>
#include "sre_typedef.h"
#include "hm_msg_type.h"
#include "tee_defines.h"
#include "sre_errno.h"

#define OS_MID_TIMER 0x2e /* old macro definition, should delete */
/*
 * Seconds will be set to maximum value
 * and the number of nanoseconds
 * will be zero
 */
#define TIMEVAL_MAX       ((INT64) ((~((uint64_t)1 << 63)) & (~((uint64_t)0xFFFFFFFF))))
#define TIMER_INDEX_RTC   0
#define TIMER_INDEX_TIMER 1
#define MAX_NUM_OF_TIMERS 2

/* The timer event is Inactive */
#define TIMER_STATE_INACTIVE 0x00U
/* The timer event is active and is waiting for expiration */
#define TIMER_STATE_ACTIVE 0x01U
/* The timer is expired and is waiting on the callback list to be executed */
#define TIMER_STATE_PENDING 0x02U
/* The timer event is currently being executed */
#define TIMER_STATE_EXECUTING 0x04U
/* The timer event is currently being destroy */
#define TIMER_STATE_DESTROY 0x05U

#define EPOCH_YEAR      1970
#define DAYSPERLYEAR    366
#define DAYSPERNYEAR    365

#define MINSPERHOUR     60
#define SECSPERMIN      60
#define SECSPERHOUR     (SECSPERMIN * MINSPERHOUR)
#define SECSPERDAY      (SECSPERHOUR * HOURSPERDAY)

#define DAYSPERWEEK     7
#define HOURSPERDAY     24

#define MONSPERYEAR     12
#define TIME_ZONE_EIGHT 8

#define NS_PER_SECONDS 1000000000L
#define NS_PER_MSEC    1000000
#define MS_PER_SECONDS 1000
#define US_PER_SECONDS 1000000
#define IPC_NAME_MAX      32
#define CMD_TIMER_GENERIC 0xDDEA
#define CMD_TIMER_RTC     0xDDEB

#define UPPER_32_BITS(n) ((uint32_t)(((uint64_t)(n)) >> 32))
#define LOWER_32_BITS(n) ((uint32_t)(n))

/*
 * Some functions have been exported to other module use this struct as a parameter,
 * so we cannot modify the typdef, and cannot delete the struct also.
 */
typedef struct tee_time_t {
    int32_t seconds;
    int32_t millis;
} tee_time_kernel;

/*
 * Some functions have been exported to other module use this struct as a parameter,
 * so we cannot modify the typdef, and cannot delete the struct also.
 */
typedef struct tee_date_t {
    int32_t seconds;
    int32_t millis;
    int32_t min;
    int32_t hour;
    int32_t day;
    int32_t month;
    int32_t year;
} tee_date_time_kernel;

/*
 * Some functions have been exported to other module use this struct as a parameter,
 * so we cannot modify the typdef, and cannot delete the struct also.
 */
typedef union {
    int64_t tval64;
    struct {
        int32_t nsec;
        int32_t sec;
    } tval;
} timeval_t;

enum timer_callback_mode {
    /* The handler function should be run in softirq */
    TIMER_CALLBACK_SOFTIRQ,
    /* The handler function should be run in hardirq context itself */
    TIMER_CALLBACK_HARDIRQ,
    /* The handler function should be executed in hardirq and it should not
     * restart the timer */
    TIMER_CALLBACK_HARDIRQ_NORESTART,
    /* A special callback mode for timeout notification */
    TIMER_CALLBACK_TIMEOUT
};

enum timer_cbfn_return_value {
    TIMER_RESTART,
    TIMER_NORESTART
};

enum timer_class_type {
    /* timer event using timer10 */
    TIMER_GENERIC,
    /* timer event using RTC */
    TIMER_RTC,
    TIMER_CLASSIC,
};

struct timer_clock_info {
    struct timer_cpu_info *cpu_info;
    int clock_id;
    /* list for active timer event */
    struct dlist_node active;
    /* list for created timer event */
    struct dlist_node avail;
    timeval_t clock_period;
    timeval_t timer_period;
    int shift;
    uint32_t mult;
};

struct timer_cpu_info {
    /* 0 for RTC, 1 for timer60 */
    struct timer_clock_info clock_info[MAX_NUM_OF_TIMERS];
    timeval_t expires_next[MAX_NUM_OF_TIMERS];
};

/*
 * attention:
 * timer_private_data_kernel must be the same to TEE:timer_event_private_data
 */
struct timer_private_data_kernel {
    uint32_t dev_id;
    struct tee_uuid uuid;
    uint32_t session_id;
    uint32_t type;
    uint32_t expire_time;
};

struct timer_attr_data_kernel {
    uint32_t type;
    uint32_t timer_id;
    uint32_t timer_class;
    uint64_t handle;
};

/*
 * Some functions have been exported to other module use this struct as a parameter,
 * so we cannot modify the typdef, and cannot delete the struct also.
 */
typedef struct {
    uint32_t dev_id;
    struct tee_uuid uuid;
    uint32_t session_id;
    struct timer_attr_data_kernel property;
    uint32_t expire_time;
} timer_notify_data_kernel;

/*
 * Some functions have been exported to other module use this struct as a parameter,
 * so we cannot modify the typdef, and cannot delete the struct also.
 */
typedef struct {
    /* node for active timer event */
    struct dlist_node node;
    struct dlist_node callback_entry;
    /* node for created timer event */
    struct dlist_node c_node;
    uint64_t handle;
    timeval_t expires;
    struct timer_clock_info *clk_info;
    int32_t (*handler)(void *);
    uint32_t state;
    int callback_mode;
    /* 0:timer60, 1:RTC */
    int32_t timer_class;
    struct timer_private_data_kernel timer_attr;
    int32_t pid;
    uint32_t app_handler;
    cref_t timer_channel;
    char path_name[IPC_NAME_MAX];
    void *data;
} timer_event;

/*
 * The elements of this structure are useful
 * for implementing the sw_timer
 */
struct sw_timer_info {
    timeval_t sw_timestamp;
    uint64_t abs_cycles_count;
    uint64_t cycles_count_old;
    uint64_t cycles_count_new;
    timeval_t timer_period;
    timeval_t clock_period;
};

typedef int32_t (*sw_timer_event_handler)(void *);

struct sw_timer_event_hdl_info {
    sw_timer_event_handler hdl;
    void *priv_data;
};

struct tee_time_stamp {
    uint32_t seconds;
    uint32_t nanos;
};

/*
 * value:   0x02002e01
 * meaning: input ptr is null.
 */
#define OS_ERRNO_TIMER_INPUT_PTR_NULL SRE_ERRNO_OS_ERROR(OS_MID_TIMER, 0x01)

/*
 * value:   0x02002e02
 * meaning: timer interval is invalid.
 */
#define OS_ERRNO_TIMER_INTERVAL_INVALID SRE_ERRNO_OS_ERROR(OS_MID_TIMER, 0x04)

/*
 * value:   0x02002e0a
 * meaning: timer event is not available.
 */
#define OS_ERRNO_TIMER_EVENT_NOT_AVAILABLE SRE_ERRNO_OS_ERROR(OS_MID_TIMER, 0x0a)

timer_event *SRE_TimerEventCreate(sw_timer_event_handler handler, int timer_class, void *priv_data);
uint32_t SRE_TimerEventStart(timer_event *pstTevent, timeval_t *time);
uint64_t SRE_ReadTimestamp(void);
uint64_t SRE_TimerGetExpire(timer_event *pstTevent);
void tee_timer_drv_init();
void gic_spi_notify();
void release_timer_event(const TEE_UUID *uuid);
#endif /* LIBTIMER_A32_SYS_TIMER_H */
