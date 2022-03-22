/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_UTIL_STIMER_H
#define _SSI_UTIL_STIMER_H

/* !
@file
@brief This file contains the functions and definitions for the secure timer module.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "ssi_util_error.h"
#include "ssi_pal_types_plat.h"

#define NSEC_SEC                      1000000000
#define CONVERT_CLK_TO_NSEC(clks, hz) ((NSEC_SEC / hz) * (clks))

/* *****************************************************************************
 *                            DEFINITIONS
 * *************************************************************************** */

typedef struct {
    uint32_t lower_bit_reg;
    uint32_t upper_bit_reg;
} SaSiUtilCntr_t;

typedef struct {
    uint64_t lr_cntr_value_back;
    uint64_t hr_cntr_value_back;
    uint64_t lr_cntr_value_forward;
    uint64_t hr_cntr_value_forward;
} SaSiUtilTimeStamp_t;

/* !
 * @brief This function records and retrieves the current time stamp read from the Secure Timer.
 *
 * @return None.
 *
 */
void SaSi_UtilGetTimeStamp(SaSiUtilTimeStamp_t *time_stamp /* !< [out] Time stamp read from the Secure Timer. */);

/* !
 * @brief This function returns the elapsed time, in nano-seconds, between two recorded time stamps. The first time
 * stamp is assumed to be the stamp of the interval start, so if time_stamp2 is lower than time_stamp1, negative
 * duration is returned. The translation to nano-seconds is based on the clock frequency definitions described in
 * ssi_secure_defs.h.
 *
 * @return  - Duration between two time stamps in nsec.
 *
 */
int64_t SaSi_UtilCmpTimeStamp(SaSiUtilTimeStamp_t *time_stamp1, /* !< [in] Time stamp of the interval start. */
                              SaSiUtilTimeStamp_t *time_stamp2 /* !< [in] Time stamp of the interval end. */);

#ifdef __cplusplus
}
#endif

#endif /* _SSI_UTIL_STIMER_H */
