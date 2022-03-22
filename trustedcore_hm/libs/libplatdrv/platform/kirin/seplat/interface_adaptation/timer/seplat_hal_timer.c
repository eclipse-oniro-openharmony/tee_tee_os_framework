/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: Provides abstract timer interfaces for seplat.
 * Create: 2020/12/05
 */

#include "types.h"
#include "seplat_hal_log.h"
#include "soc_acpu_baseaddr_interface.h"
#include "soc_syscounter_interface.h"
#include "register_ops.h" /* read32 */

#define HAL_MAX_US_DELAY  10000000 /* us */
#define HAL_S_TO_US       1000000
#define HAL_US_TO_NS      1000
#define BITS_IN_WORD 32
#define HAL_TIMER_US2TICK(us)                  ((((uint64_t)(us)) * (192)) / (100))  /* 1.92M */
#define HAL_TIMER_TICK2US(val)                 ((((uint64_t)(val)) * (100)) / (192))  /* 1.92M */

/*
 * @brief  : get the system timer value
 * @return : Current system timer value.
 */
uint64_t hal_get_timer_value(void)
{
    uint64_t value;
    uint64_t value_h;
    uint32_t value_l;

    value_h = (uint64_t)read32(SOC_SYSCOUNTER_CNTCV_H32_ADDR(SOC_ACPU_SYS_CNT_BASE_ADDR));
    value_l = read32(SOC_SYSCOUNTER_CNTCV_L32_ADDR(SOC_ACPU_SYS_CNT_BASE_ADDR));

    value = (value_h << BITS_IN_WORD) | (value_l);

    return HAL_TIMER_TICK2US(value);
}

/*
 * @brief     : sdelay us
 * @param[in] : the time(us) to delay (max 10s).
 */
void hal_udelay(uint32_t us)
{
    uint64_t timer_begin, timer_end;

    if (us > HAL_MAX_US_DELAY) {
        hal_print_error("Invalid delay param:%u!\n", us);
        return;
    }

    timer_begin = hal_get_timer_value();
    do
        timer_end = hal_get_timer_value();
    while ((timer_end - timer_begin) < us); /* see notice in function annotations */
}

/*
 * @brief     : delay us from begin time.
 * @param[in] : begin_time :must from function "hal_get_timer_value"; us :the time(us) to delay (max 10s).
 * @notice    : if begin_time > end_time, the function will return.
 */
void hal_timer_delay(uint64_t begin_time, uint32_t us)
{
    uint64_t end_time;

    if (us > HAL_MAX_US_DELAY) {
        hal_print_error("Invalid delay param:%u!\n", us);
        return;
    }

    do
        end_time = hal_get_timer_value();
    while ((end_time - begin_time) < us); /* see notice in function annotations */
}
