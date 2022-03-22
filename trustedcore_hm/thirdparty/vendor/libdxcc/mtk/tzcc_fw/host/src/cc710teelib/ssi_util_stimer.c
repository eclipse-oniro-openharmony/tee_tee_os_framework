/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "ssi_util.h"
#include "ssi_util_int_defs.h"
#include "ssi_secure_clk_defs.h"
#include "ssi_util_stimer.h"
#include "ssi_hal_plat.h"
#include "ssi_regs.h"
#include "ssi_pal_mutex.h"
#include "ssi_pal_abort.h"
#include "sasi_fips_defs.h"

#define HIGH_FRQ_CNTR_RESET_VALUE      0x7FFFFFFFFF
#define HIGH_FRQ_CNTR_SATURATION_VALUE 0xFFFFFFFFFF // (2<<39) -1

uint64_t graydecode(uint64_t gray)
{
    uint64_t bin = gray;
    bin ^= (bin >> 32);
    bin ^= (bin >> 16);
    bin ^= (bin >> 8);
    bin ^= (bin >> 4);
    bin ^= (bin >> 2);
    bin ^= (bin >> 1);

    return bin;
}

extern SaSi_PalMutex sasiSymCryptoMutex;

/* !
 * This function get current time stamp
 *
 * @param[in] stimer     - secure timer structure
 *
 *
 *
 *     1. A "timestamp" object holds two true timestamps - "back" and "forward".
 *       Each timestamp itself consists of two fields -
 *       "low-resolution (always-on) timer value" (holds 64 bits value),
 *       and "high-resolution timer value" (holds 40 bits value).
 *
 *    2. The "take timestamp" logic operates as follows:
 *        a. Read the current state of the HW timers into the "back" fields of the timestamp object.
 *        b. If the high-resolution timer value is lower than HIGH_FRQ_CNTR_RESET_VALUE - i.e. half
 *           the range - copy the "back" fields to the "forwards" fields and return.
 *        c. Otherwise (timer value is high), reset the high-resolution timer
 *           (causing HW to sample the low-resolution timer) and read the HW timers into the "forwards" fields.
 *        d. If high-resolution timer in "back" field was at the maximum value (= saturated), copy the "forwards"
 *           fields to the "back" fields.
 *
 */

void SaSi_UtilGetTimeStamp(SaSiUtilTimeStamp_t *time_stamp)
{
    SaSiUtilCntr_t *hr_value, *lr_value;
    SaSiError_t retCode = SASI_SUCCESS;

    CHECK_AND_RETURN_UPON_FIPS_ERROR();

    /* lock mutex before taking time stamp */
    retCode = SaSi_PalMutexLock(&sasiSymCryptoMutex, SASI_INFINITE);
    if (retCode != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }

    hr_value = (SaSiUtilCntr_t *)&time_stamp->hr_cntr_value_back;
    lr_value = (SaSiUtilCntr_t *)&time_stamp->lr_cntr_value_back;

    SaSi_PalMemSet(time_stamp, 0, sizeof(SaSiUtilTimeStamp_t));

    hr_value->lower_bit_reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_HIGH_RES_SECURE_TIMER_0));
    hr_value->upper_bit_reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_HIGH_RES_SECURE_TIMER_1));

    lr_value->lower_bit_reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_LATCHED_EXTERNAL_TIMER_0));
    lr_value->upper_bit_reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_LATCHED_EXTERNAL_TIMER_1));

    time_stamp->hr_cntr_value_back = graydecode(time_stamp->hr_cntr_value_back);
    time_stamp->lr_cntr_value_back = graydecode(time_stamp->lr_cntr_value_back);

    SASI_PAL_LOG_DEBUG("    time_stamp->hr_cntr_value_back = %lli\n", time_stamp->hr_cntr_value_back);
    SASI_PAL_LOG_DEBUG("    time_stamp->lr_cntr_value_back = %lli\n", time_stamp->lr_cntr_value_back);

    /* in case timer value of high resolution timer reach HIGH_FRQ_CNTR_RESET_VALUE reset the high-resolution timer */
    if (time_stamp->hr_cntr_value_back > HIGH_FRQ_CNTR_RESET_VALUE) {
        hr_value = (SaSiUtilCntr_t *)&time_stamp->hr_cntr_value_forward;
        lr_value = (SaSiUtilCntr_t *)&time_stamp->lr_cntr_value_forward;

        SASI_PAL_LOG_DEBUG("\n Reset High resolution Secure Timer \n");
        SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_HIGH_RES_SECURE_TIMER_RST), 0);

        // wait ?????
        hr_value->lower_bit_reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_HIGH_RES_SECURE_TIMER_0));
        hr_value->upper_bit_reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_HIGH_RES_SECURE_TIMER_1));

        lr_value->lower_bit_reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_LATCHED_EXTERNAL_TIMER_0));
        lr_value->upper_bit_reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_LATCHED_EXTERNAL_TIMER_1));

        time_stamp->hr_cntr_value_forward = graydecode(time_stamp->hr_cntr_value_forward);
        time_stamp->lr_cntr_value_forward = graydecode(time_stamp->lr_cntr_value_forward);

        SASI_PAL_LOG_DEBUG("    time_stamp->hr_cntr_value_forward = %lli\n", time_stamp->hr_cntr_value_forward);
        SASI_PAL_LOG_DEBUG("    time_stamp->lr_cntr_value_forward = %lli\n", time_stamp->lr_cntr_value_forward);

        if (time_stamp->hr_cntr_value_back == HIGH_FRQ_CNTR_SATURATION_VALUE) {
            SASI_PAL_LOG_DEBUG("\n High resolution Secure Timer was in saturated state \n");
            SaSi_PalMemCopy(&time_stamp->hr_cntr_value_back, &time_stamp->hr_cntr_value_forward, sizeof(uint64_t));
            SaSi_PalMemCopy(&time_stamp->lr_cntr_value_back, &time_stamp->lr_cntr_value_forward, sizeof(uint64_t));
        }
    } else {
        SaSi_PalMemCopy(&time_stamp->hr_cntr_value_forward, &time_stamp->hr_cntr_value_back, sizeof(uint64_t));
        SaSi_PalMemCopy(&time_stamp->lr_cntr_value_forward, &time_stamp->lr_cntr_value_back, sizeof(uint64_t));
        SASI_PAL_LOG_DEBUG("    time_stamp->hr_cntr_value_forward = %lli\n", time_stamp->hr_cntr_value_forward);
        SASI_PAL_LOG_DEBUG("    time_stamp->lr_cntr_value_forward = %lli\n", time_stamp->lr_cntr_value_forward);
    }

    /* free mutex */
    if (SaSi_PalMutexUnlock(&sasiSymCryptoMutex) != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to release mutex\n");
    }
}

/* !
 * This function computes duration between to time stamps
 *
 * @param[in] time_stamp1     - first time stamp
 *
 *  @param[in] time_stamp2     - second time stamp
 *
 * @return  - duration between two time stamps in nsec
 *
 *
 *     The "compute interval" logic (computing interval between two timestamps, called here "early" and "late"):
 *        a. If the early timestamp's "forwards" low-resolution timestamp == late "back" low-resolution timestamp,
 *           compute the interval from the difference of the two high-resolution timers (with fast-clock accuracy).
 *        b. Otherwise, compute the interval from both the low-resolution and high-resolution timer differences;
 *           the accuracy is the same as the slow (always-on) clock.
 *
 */
int64_t SaSi_UtilCmpTimeStamp(SaSiUtilTimeStamp_t *time_stamp1, SaSiUtilTimeStamp_t *time_stamp2)
{
    int64_t cmp_result;

    cmp_result = CONVERT_CLK_TO_NSEC(((uint64_t)(time_stamp2->hr_cntr_value_back - time_stamp1->hr_cntr_value_forward)),
                                     CORE_CLOCK_HZ);

    if (time_stamp1->lr_cntr_value_forward != time_stamp2->lr_cntr_value_back) {
        cmp_result +=
            CONVERT_CLK_TO_NSEC(((uint64_t)(time_stamp2->lr_cntr_value_back - time_stamp1->lr_cntr_value_forward)),
                                EXTERNAL_SLOW_OSCILLATOR_HZ);
    }

    return cmp_result;
}

/* ******************************************* Private functions ******************************* */
/* !
 * This function resets the low resolution secure timer
 *
 */
void SaSi_UtilResetLowResTimer(void)
{
    SaSiUtilCntr_t *lr_pre_cntr, *lr_post_cntr;
    uint64_t lr_pre_value = 0, lr_post_value = 0xffffffffff;
    lr_pre_cntr  = (SaSiUtilCntr_t *)&lr_pre_value;
    lr_post_cntr = (SaSiUtilCntr_t *)&lr_post_value;

    /* Reset only the low resolution secure timer:
       Since the time of the reset is dependent on the external clock (which is unkown...).
       We sample the signal before and after the reset, and wait while (post>=pre).
       The High resolution will be reset by the CC reset afterwards. */

    lr_pre_cntr->lower_bit_reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_LOW_RES_SECURE_TIMER_0));
    lr_pre_cntr->upper_bit_reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_LOW_RES_SECURE_TIMER_1));
    lr_pre_value               = graydecode(lr_pre_value);

    SASI_PAL_LOG_DEBUG("\n Reset Low resolution Secure Timer \n");
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_LOW_RES_SECURE_TIMER_RST), 0);

    while (lr_post_value >= lr_pre_value) {
        lr_post_cntr->lower_bit_reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_LOW_RES_SECURE_TIMER_0));
        lr_post_cntr->upper_bit_reg = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_LOW_RES_SECURE_TIMER_1));
        lr_post_value               = graydecode(lr_post_value);
    }

    return;
}
