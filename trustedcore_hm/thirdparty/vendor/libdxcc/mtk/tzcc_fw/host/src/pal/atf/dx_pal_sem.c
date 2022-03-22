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

#include "ssi_pal_sem.h"
/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* typedef struct
{
  uint32_t DX_PAL_SemId;

}_DX_PAL_Sem_t; */

/* *********************** Global Data **************************** */

/* *********************** Private Functions **************************** */

/* *********************** Public Functions **************************** */

/*
 * @brief This function purpose is to create a semaphore.
 *
 *
 * @param[out] aSemId - Pointer to created semaphor handle
 * @param[in] aInitialVal - Initial semaphore value
 *
 * @return The return values will be according to operating system return values.
 */
SaSiError_t _SaSi_PalSemCreate(DX_PAL_SEM *aSemId, uint32_t aInitialVal)
{
    *aSemId = (DX_PAL_SEM)1;

    return SASI_SUCCESS;

} /* End of SaSi_PalSemCreate */

/*
 * @brief This function purpose is to delete a semaphore
 *
 *
 * @param[in] aSemId - Semaphore handle
 *
 * @return The return values will be according to operating system return values.
 */
SaSiError_t _SaSi_PalSemDelete(DX_PAL_SEM *aSemId)
{
    *aSemId = (DX_PAL_SEM)0;
    return SASI_SUCCESS;

} /* End of SaSi_PalSemDelete */

/*
 * @brief This function purpose is to Wait for semaphore with aTimeOut. aTimeOut is
 *        specified in milliseconds.
 *
 *
 * @param[in] aSemId - Semaphore handle
 * @param[in] aTimeOut - timeout in mSec, or SASI_INFINITE
 *
 * @return The return values will be according to operating system return values.
 */
SaSiError_t _SaSi_PalSemWait(DX_PAL_SEM aSemId, uint32_t aTimeOut)
{
    return SASI_SUCCESS;
} /* End of SaSi_PalSemWait */

/*
 * @brief This function purpose is to signal the semaphore.
 *
 *
 * @param[in] aSemId - Semaphore handle
 *
 * @return The return values will be according to operating system return values.
 */
SaSiError_t _SaSi_PalSemGive(DX_PAL_SEM aSemId)
{
    return SASI_SUCCESS;
} /* End of SaSi_PalSemGive */
