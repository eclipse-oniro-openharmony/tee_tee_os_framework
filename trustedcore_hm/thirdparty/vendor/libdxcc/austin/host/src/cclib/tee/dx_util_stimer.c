/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

/* ************ Include Files ************** */
#include "dx_pal_types.h"
#include "dx_pal_mem.h"
#include "dx_util.h"
#include "dx_util_defs.h"
#include "dx_secure_defs.h"
#include "dx_util_stimer.h"
#include "dx_hal_plat.h"
#include "dx_cc_regs.h"
#include "dx_pal_mutex.h"
#include "dx_pal_abort.h"

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

extern DX_PAL_MUTEX dxSymCryptoMutex;

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

void DX_UTIL_GetTimeStamp(DX_UTIL_TimeStamp_t *time_stamp)
{
    DX_UTIL_Cntr_t *hr_value, *lr_value;
    DxError_t retCode = DX_SUCCESS;

    /* lock mutex before taking time stamp */
    retCode = DX_PAL_MutexLock(&dxSymCryptoMutex, DX_INFINITE);
    if (retCode != DX_SUCCESS) {
        DX_PAL_Abort("Fail to acquire mutex\n");
    }

    hr_value = (DX_UTIL_Cntr_t *)&time_stamp->hr_cntr_value_back;
    lr_value = (DX_UTIL_Cntr_t *)&time_stamp->lr_cntr_value_back;

    DX_PAL_MemSet(time_stamp, 0, sizeof(DX_UTIL_TimeStamp_t));

    hr_value->lower_bit_reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_HIGH_RES_SECURE_TIMER_0));
    hr_value->upper_bit_reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_HIGH_RES_SECURE_TIMER_1));

    lr_value->lower_bit_reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_LATCHED_EXTERNAL_TIMER_0));
    lr_value->upper_bit_reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_LATCHED_EXTERNAL_TIMER_1));

    time_stamp->hr_cntr_value_back = graydecode(time_stamp->hr_cntr_value_back);
    time_stamp->lr_cntr_value_back = graydecode(time_stamp->lr_cntr_value_back);

    DX_PAL_LOG_DEBUG("    time_stamp->hr_cntr_value_back = %lli\n", time_stamp->hr_cntr_value_back);
    DX_PAL_LOG_DEBUG("    time_stamp->lr_cntr_value_back = %lli\n", time_stamp->lr_cntr_value_back);

    /* in case timer value of high resolution timer reach HIGH_FRQ_CNTR_RESET_VALUE reset the high-resolution timer */
    if (time_stamp->hr_cntr_value_back > HIGH_FRQ_CNTR_RESET_VALUE) {
        hr_value = (DX_UTIL_Cntr_t *)&time_stamp->hr_cntr_value_forward;
        lr_value = (DX_UTIL_Cntr_t *)&time_stamp->lr_cntr_value_forward;

        DX_PAL_LOG_DEBUG("\n Reset High resolution Secure Timer \n");
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_HIGH_RES_SECURE_TIMER_RST), 0);

        // wait ?????
        hr_value->lower_bit_reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_HIGH_RES_SECURE_TIMER_0));
        hr_value->upper_bit_reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_HIGH_RES_SECURE_TIMER_1));

        lr_value->lower_bit_reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_LATCHED_EXTERNAL_TIMER_0));
        lr_value->upper_bit_reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_LATCHED_EXTERNAL_TIMER_1));

        time_stamp->hr_cntr_value_forward = graydecode(time_stamp->hr_cntr_value_forward);
        time_stamp->lr_cntr_value_forward = graydecode(time_stamp->lr_cntr_value_forward);

        DX_PAL_LOG_DEBUG("    time_stamp->hr_cntr_value_forward = %lli\n", time_stamp->hr_cntr_value_forward);
        DX_PAL_LOG_DEBUG("    time_stamp->lr_cntr_value_forward = %lli\n", time_stamp->lr_cntr_value_forward);

        if (time_stamp->hr_cntr_value_back == HIGH_FRQ_CNTR_SATURATION_VALUE) {
            DX_PAL_LOG_DEBUG("\n High resolution Secure Timer was in saturated state \n");
            DX_PAL_MemCopy(&time_stamp->hr_cntr_value_back, &time_stamp->hr_cntr_value_forward, sizeof(uint64_t));
            DX_PAL_MemCopy(&time_stamp->lr_cntr_value_back, &time_stamp->lr_cntr_value_forward, sizeof(uint64_t));
        }
    } else {
        DX_PAL_MemCopy(&time_stamp->hr_cntr_value_forward, &time_stamp->hr_cntr_value_back, sizeof(uint64_t));
        DX_PAL_MemCopy(&time_stamp->lr_cntr_value_forward, &time_stamp->lr_cntr_value_back, sizeof(uint64_t));
        DX_PAL_LOG_DEBUG("    time_stamp->hr_cntr_value_forward = %lli\n", time_stamp->hr_cntr_value_forward);
        DX_PAL_LOG_DEBUG("    time_stamp->lr_cntr_value_forward = %lli\n", time_stamp->lr_cntr_value_forward);
    }

    /* free mutex */
    if (DX_PAL_MutexUnlock(&dxSymCryptoMutex) != DX_SUCCESS) {
        DX_PAL_Abort("Fail to release mutex\n");
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
int64_t DX_UTIL_CmpTimeStamp(DX_UTIL_TimeStamp_t *time_stamp1, DX_UTIL_TimeStamp_t *time_stamp2)
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
void DX_UTIL_ResetLowResTimer(void)
{
    DX_UTIL_Cntr_t *lr_pre_cntr, *lr_post_cntr;
    uint64_t lr_pre_value = 0, lr_post_value = 0xffffffffff;
    lr_pre_cntr  = (DX_UTIL_Cntr_t *)&lr_pre_value;
    lr_post_cntr = (DX_UTIL_Cntr_t *)&lr_post_value;

    /* Reset only the low resolution secure timer:
       Since the time of the reset is dependent on the external clock (which is unkown...).
       We sample the signal before and after the reset, and wait while (post>=pre).
       The High resolution will be reset by the CC reset afterwards. */

    lr_pre_cntr->lower_bit_reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_LOW_RES_SECURE_TIMER_0));
    lr_pre_cntr->upper_bit_reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_LOW_RES_SECURE_TIMER_1));
    lr_pre_value               = graydecode(lr_pre_value);

    DX_PAL_LOG_DEBUG("\n Reset Low resolution Secure Timer \n");
    DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_LOW_RES_SECURE_TIMER_RST), 0);

    while (lr_post_value >= lr_pre_value) {
        lr_post_cntr->lower_bit_reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_LOW_RES_SECURE_TIMER_0));
        lr_post_cntr->upper_bit_reg = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, HOST_LOW_RES_SECURE_TIMER_1));
        lr_post_value               = graydecode(lr_post_value);
    }

    return;
}
