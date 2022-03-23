/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef __SSI_HAL_H__
#define __SSI_HAL_H__

/* !
@file
@brief This file contains HAL definitions and APIs.
*/

#include <stdint.h>
#include "ssi_hal_plat.h"

/* ! HAL return code definitions. */
typedef enum {
    SASI_HAL_OK = 0,
    SASI_HAL_ENODEV,    /* Device not opened or does not exist */
    SASI_HAL_EINTERNAL, /* Internal driver error (check system log) */
    SASI_HAL_MAPFAILED,
    SASI_HAL_ENOTSUP, /* Unsupported function/option */
    SASI_HAL_ENOPERM, /* Not enough permissions for request */
    SASI_HAL_EINVAL,  /* Invalid parameters */
    SASI_HAL_ENORSC,  /* No resources available (e.g., memory) */
    SASI_HAL_RESERVE32B = 0x7FFFFFFFL
} SaSiHalRetCode_t;

/* !
 * @brief This function is used to map ARM TrustZone CryptoCell TEE registers to Host virtual address space.
    It is called by ::SaSi_LibInit, and returns a non-zero value in case of failure.
        The existing implementation supports Linux environment. In case virtual addressing is not used, the function can
 be minimized to contain only the following line, and return OK: gCcRegBase = (uint32_t)DX_BASE_CC;
  @return SASI_HAL_OK on success.
  @return A non-zero value in case of failure.
*/
int SaSi_HalInit(void);

/* !
 * @brief This function is used to wait for the IRR interrupt signal. The existing implementation performs a "busy wait"
 on the IRR, and returns its value once it changes to non-zero. This implementation can be left as-is. However, it
 degrades performance significantly. Therefore, it is recommended to change it to an implementation that waits for an
 actual interrupt.

 * @return uint32_t The IRR value.
 */
uint32_t SaSi_HalWaitInterrupt(uint32_t data /* !< [in] The interrupt bits to wait upon. */);

/* !
 * @brief This function is called by SaSi_LibInit and is used for initializing the ARM TrustZone CryptoCell TEE cache
 settings registers. The existing implementation sets the registers to their default values in HCCC cache coherency mode
      (ARCACHE = 0x2, AWCACHE = 0x7, AWCACHE_LAST = 0x7).
          These values should be changed by the customer in case the customer's platform requires different HCCC values,
 or in case SCCC is needed (the values for SCCC are ARCACHE = 0x3, AWCACHE = 0x3, AWCACHE_LAST = 0x3).

 * @return void
 */
void SaSi_HalInitHWCacheParams(void);

/* !
 * @brief This function is used to unmap ARM TrustZone CryptoCell TEE registers' virtual address.
      It is called by SaSi_LibFini, and returns a non-zero value in case of failure.
      In case virtual addressing is used, the function can be minimized to be an empty function returning OK.
   @return SASI_HAL_OK on success.
   @return A non-zero value in case of failure.
 */
int SaSi_HalTerminate(void);

/* !
 * @brief This function is used to clear the interrupt vector.

 * @return void.
 */
void SaSi_HalClearInterruptBit(uint32_t data /* !< [in] The interrupt bits to clear. */);

/* !
 * @brief This function is used to mask IRR interrupts.

 * @return void.
 */
void SaSi_HalMaskInterrupt(uint32_t data /* !< [in] The interrupt bits to mask. */);

#endif
