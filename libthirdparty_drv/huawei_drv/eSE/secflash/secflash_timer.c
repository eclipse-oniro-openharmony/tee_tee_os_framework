/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: secure flash module driver.
 * Create: 2019/11/23
 */
#include "secflash_timer.h"
#include "secflash_def.h"
#include "soc_acpu_baseaddr_interface.h"
#include "soc_syscounter_interface.h"
#ifdef SECFLASH_TEE
#include "sre_typedef.h"
#include "tee_log.h"
#include "register_ops.h" /* read32 */
#else
#include "mmio.h"
#endif

#define BITS_IN_WORD 32

/*
 * @brief  : secflash_get_timer_value: get the syscounter value
 * @return : Current syscounter value.
 */
uint64_t secflash_get_timer_value(void)
{
    uint64_t value;
    uint64_t value_h;
    uint32_t value_l;

#ifdef SECFLASH_TEE
    value_h = (uint64_t)read32(SOC_SYSCOUNTER_CNTCV_H32_ADDR(SOC_ACPU_SYS_CNT_BASE_ADDR));
    value_l = read32(SOC_SYSCOUNTER_CNTCV_L32_ADDR(SOC_ACPU_SYS_CNT_BASE_ADDR));
#else
    value_h = (uint64_t)mmio_read_32(SOC_SYSCOUNTER_CNTCV_H32_ADDR(SOC_ACPU_SYS_CNT_BASE_ADDR));
    value_l = mmio_read_32(SOC_SYSCOUNTER_CNTCV_L32_ADDR(SOC_ACPU_SYS_CNT_BASE_ADDR));
#endif
    value = (value_h << BITS_IN_WORD) | (value_l);

    return value;
}

/*
 * @brief     : secflash_udelay: delay us
 * @param[in] : the time(us) to delay (max 10s).
 * @notice    : the conditions of inversion will occur in 150000 years later, it is impossible.
 */
void secflash_udelay(uint32_t us)
{
    uint64_t timer_begin, timer_end;
    uint64_t delay_ticks;

    if (us > SECLFASH_MAX_US_DELAY) {
        SECFLASH_LOG("secflash:Invalid delay param:%u!\n", us);
        return;
    }

    delay_ticks = SECLFASH_US2TICK(us);

    timer_begin = secflash_get_timer_value();
    do {
        timer_end = secflash_get_timer_value();
    } while ((timer_end - timer_begin) < delay_ticks); /* see notice in function annotations */
}

/*
 * @brief     : delay us from begin time.
 * @param[in] : begin_time :must from function "secflash_get_timer_value"; us :the time(us) to delay (max 10s).
 * @notice    : if begin_time > end_time, the function will return.
 *              if begin_time get from function "secflash_get_timer_value",
 *              the conditions of inversion will occur in 150000 years later, it is impossible.
 */
void secflash_timer_delay(uint64_t begin_time, uint32_t us)
{
    uint64_t end_time;
    uint64_t delay_ticks;

    if (us > SECLFASH_MAX_US_DELAY) {
        SECFLASH_LOG("secflash:Invalid delay param:%u!\n", us);
        return;
    }

    delay_ticks = SECLFASH_US2TICK(us);

    do {
        end_time = secflash_get_timer_value();
    } while ((end_time - begin_time) < delay_ticks); /* see notice in function annotations */
}
