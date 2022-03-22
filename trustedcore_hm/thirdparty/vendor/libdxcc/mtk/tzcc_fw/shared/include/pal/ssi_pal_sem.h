/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_SEM_H
#define _SSI_PAL_SEM_H

#include "ssi_pal_sem_plat.h"

#define SASI_PAL_SEM_NO_WAIT 0
#define SASI_PAL_SEM_FREE    1
#define SASI_PAL_SEM_LOCKED  0

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief File Description:
 *        This file contains functions for resource management (semaphor operations).
 *        The functions implementations are generally just wrappers to different operating system calls.
 *        None of the described functions will check the input parameters so the behavior
 *        of the APIs in illegal parameters case is dependent on the operating system behavior.
 *
 */

/* ----------------------------
      PUBLIC FUNCTIONS
----------------------------------- */

/*
 * @brief This function purpose is to create a semaphore.
 *
 *
 * @param[out] aSemId - Pointer to created semaphor handle
 * @param[in] aInitialVal - Initial semaphore value
 *
 * @return The return values is according to operating system return values.
 */
// SaSiError_t SaSi_PalSemCreate( DX_PAL_SEM *aSemId, uint32_t aInitialVal );
#define SaSi_PalSemCreate _SaSi_PalSemCreate
/*
 * @brief This function purpose is to delete a semaphore
 *
 *
 * @param[in] aSemId - Semaphore handle
 *
 * @return The return values is according to operating system return values.
 */
// SaSiError_t SaSi_PalSemDelete( DX_PAL_SEM *aSemId );
#define SaSi_PalSemDelete _SaSi_PalSemDelete
/*
 * @brief This function purpose is to Wait for semaphore with aTimeOut. aTimeOut is
 *        specified in milliseconds.
 *
 *
 * @param[in] aSemId - Semaphore handle
 * @param[in] aTimeOut - timeout in mSec, or SASI_INFINITE
 *
 * @return The return values is according to operating system return values.
 */
// SaSiError_t SaSi_PalSemWait(DX_PAL_SEM aSemId, uint32_t aTimeOut);
#define SaSi_PalSemWait _SaSi_PalSemWait
/*
 * @brief This function purpose is to signal the semaphore.
 *
 *
 * @param[in] aSemId - Semaphore handle
 *
 * @return The return values is according to operating system return values.
 */
// SaSiError_t SaSi_PalSemGive(DX_PAL_SEM aSemId);

#define SaSi_PalSemGive _SaSi_PalSemGive

#ifdef __cplusplus
}
#endif

#endif
