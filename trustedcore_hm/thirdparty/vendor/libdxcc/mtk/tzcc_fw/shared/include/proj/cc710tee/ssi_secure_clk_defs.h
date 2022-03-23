/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_SECURE_CLK_DEFS_H
#define _SSI_SECURE_CLK_DEFS_H

/* !
@file
@brief This file contains definitions for secure clock. The file contains configurable parameters that should be
adjusted to the target platform.
*/

#ifdef __cplusplus
extern "C" {
#endif

/* Secure Clock definitions */
/* ------------------------- */
/* ! Defines the frequency of the high-resolution timer in Hz units. Modify the value to ARM TrustZone CryptoCell TEE
  core clock frequency on the target platform. */
/* DXCC core clock, available options are 137/273MHZ, default value in ARM Cryptocell firmware package is 50MHZ */
#define CORE_CLOCK_HZ 136500000

/* ! Defines the frequency of the low-resolution clock in Hz units. Modify the value to the external slow clock frequency
  on the target platform. 1MHz (1000000) is recommended. */
/* external clock is RTC, which is 32KHZ, default value in ARM Cryptocell firmware package is 50MHZ */
#define EXTERNAL_SLOW_OSCILLATOR_HZ 32000

#ifdef __cplusplus
}
#endif

#endif
