/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: secure flash module driver.
 * Create: 2019/11/23
 */

#ifndef __SECFLASH_TIMER_H__
#define __SECFLASH_TIMER_H__

#include "secflash_def.h"
#ifdef SECFLASH_TEE
#include "sre_typedef.h"
#include "tee_log.h"
#endif

#define SECLFASH_MAX_US_DELAY                 10000000 /* 10s */
#define SECLFASH_US2TICK(us)                  ((((uint64_t)(us)) * (192)) / (100))  /* 1.92M */
#define SECLFASH_TICK2US(val)                 ((((uint64_t)(val)) / (192)) * (100))  /* 1.92M */
#define I2C_FAST_SPEED_ONE_BYTE_TIME          25 /* 25us */

enum secflash_timer_status {
    SECFLASH_TIMER_BEGIN,
    SECFLASH_TIMING,
    SECFLASH_TIMER_END,
};

struct secflash_timer {
    uint64_t begin;
    uint64_t end;
    enum secflash_timer_status status;
};

/*
 * @brief  : secflash_get_timer_value: get the syscounter value
 * @return : Current syscounter value.
 */
uint64_t secflash_get_timer_value(void);

/*
 * @brief     : secflash_udelay: delay us
 * @param[in] : the time(us) to delay (max 10s).
 * @notice    : the conditions of inversion will occur in 150000 years later, it is impossible.
 */
void secflash_udelay(uint32_t us);

/*
 * @brief     : delay us from begin time.
 * @param[in] : begin_time :must from function "secflash_get_timer_value"; us :the time(us) to delay (max 10s).
 * @notice    : if begin_time > end_time, the function will return.
 *              if begin_time get from function "secflash_get_timer_value",
 *              the conditions of inversion will occur in 150000 years later, it is impossible.
 */
void secflash_timer_delay(uint64_t begin_time, uint32_t us);

#endif /* __SECFLASH_TIMER_H__ */

