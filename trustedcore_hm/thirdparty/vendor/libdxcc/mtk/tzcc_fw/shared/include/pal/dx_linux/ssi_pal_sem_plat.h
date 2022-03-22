/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_SEM_INT__H
#define _SSI_PAL_SEM_INT__H

#ifdef __cplusplus
extern "C" {
#endif
#include <semaphore.h>
/*
 * @brief File Description:
 *        This file contains functions for resource management (semaphor operations).
 *        The functions implementations are generally just wrappers to different operating system calls.
 *        None of the described functions will check the input parameters so the behavior
 *        of the APIs in illegal parameters case is dependent on the operating system behavior.
 *
 */

typedef sem_t DX_PAL_SEM;

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
#define _SaSi_PalSemCreate(aSemId, aInitialVal) sem_init(aSemId, 0, aInitialVal)

/*
 * @brief This function purpose is to delete a semaphore
 *
 *
 * @param[in] aSemId - Semaphore handle
 *
 * @return The return values is according to operating system return values.
 */
#define _SaSi_PalSemDelete(aSemId) sem_destroy(aSemId)
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
#define _SaSi_PalSemWait(aSemId, aTimeOut) sem_wait(aSemId)
/*
 * @brief This function purpose is to signal the semaphore.
 *
 *
 * @param[in] aSemId - Semaphore handle
 *
 * @return The return values is according to operating system return values.
 */
#define _SaSi_PalSemGive(aSemId) sem_post(aSemId)

#ifdef __cplusplus
}
#endif

#endif
