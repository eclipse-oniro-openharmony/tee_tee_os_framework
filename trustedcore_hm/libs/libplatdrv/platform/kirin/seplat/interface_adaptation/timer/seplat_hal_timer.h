/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: Provides abstract timer interfaces for seplat.
 * Create: 2020/12/05
 */
#ifndef HAL_TIMER_H
#define HAL_TIMER_H

#include "types.h"

/*
 * @brief  : get the system timer value
 * @return : Current system timer value.
 */
uint64_t hal_get_timer_value(void);

/*
 * @brief     : sdelay us
 * @param[in] : the time(us) to delay (max 10s).
 */
void hal_udelay(uint32_t us);

/*
 * @brief     : delay us from begin time.
 * @param[in] : begin_time :must from function "hal_get_timer_value"; us :the time(us) to delay (max 10s).
 * @notice    : if begin_time > end_time, the function will return.
 */
void hal_timer_delay(uint64_t begin_time, uint32_t us);

#endif
