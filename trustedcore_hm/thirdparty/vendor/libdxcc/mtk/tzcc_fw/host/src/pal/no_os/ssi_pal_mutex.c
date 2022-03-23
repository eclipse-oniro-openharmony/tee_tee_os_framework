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

#include "ssi_pal_mutex.h"
/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* *********************** Private Functions **************************** */

/* *********************** Public Functions **************************** */

/*
 * @brief This function purpose is to create a mutex.
 *
 *
 * @param[out] pMutexId - Pointer to created mutex handle
 *
 * @return returns 0 on success, otherwise indicates failure
 */
SaSiError_t SaSi_PalMutexCreate(SaSi_PalMutex *pMutexId)
{
    SASI_UNUSED_PARAM(pMutexId);
    return 1;
}

/*
 * @brief This function purpose is to destroy a mutex
 *
 *
 * @param[in] pMutexId - pointer to Mutex handle
 *
 * @return returns 0 on success, otherwise indicates failure
 */
SaSiError_t SaSi_PalMutexDestroy(SaSi_PalMutex *pMutexId)
{
    SASI_UNUSED_PARAM(pMutexId);
    return 1;
}

/*
 * @brief This function purpose is to Wait for Mutex with aTimeOut. aTimeOut is
 *        specified in milliseconds. (SASI_INFINITE is blocking)
 *
 *
 * @param[in] pMutexId - pointer to Mutex handle
 * @param[in] timeOut - timeout in mSec, or SASI_INFINITE
 *
 * @return returns 0 on success, otherwise indicates failure
 */
SaSiError_t SaSi_PalMutexLock(SaSi_PalMutex *pMutexId, uint32_t timeOut)
{
    SASI_UNUSED_PARAM(pMutexId);
    SASI_UNUSED_PARAM(timeOut);
    return 1;
}

/*
 * @brief This function purpose is to release the mutex.
 *
 *
 * @param[in] pMutexId - pointer to Mutex handle
 *
 * @return returns 0 on success, otherwise indicates failure
 */
SaSiError_t SaSi_PalMutexUnlock(SaSi_PalMutex *pMutexId)
{
    SASI_UNUSED_PARAM(pMutexId);
    return 1;
}
