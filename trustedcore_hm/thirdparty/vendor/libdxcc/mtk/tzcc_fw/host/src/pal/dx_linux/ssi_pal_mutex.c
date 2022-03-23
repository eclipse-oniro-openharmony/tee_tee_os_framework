/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include <time.h>
#include "ssi_pal_types.h"
#include "ssi_pal_mutex.h"
#include "ssi_pal_log.h"
#include <stdio.h>

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
    int rc = SASI_SUCCESS;

    rc = pthread_mutex_init(pMutexId, NULL);
    if (rc != 0) {
        printf /* SASI_PAL_LOG_ERR */ ("pthread_mutex_init failed 0x%x", rc);
        return SASI_FAIL;
    }
    return SASI_SUCCESS;
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
    int rc = SASI_SUCCESS;

    rc = pthread_mutex_destroy(pMutexId);
    if (rc != 0) {
        printf /* SASI_PAL_LOG_ERR */ ("pthread_mutex_destroy failed 0x%x", rc);
        return SASI_FAIL;
    }
    return SASI_SUCCESS;
}

/*
 * @brief This function purpose is to Wait for Mutex with aTimeOut. aTimeOut is
 *        specified in milliseconds. (SASI_INFINITE is blocking)
 *
 *
 * @param[in] pMutexId - pointer to Mutex handle
 * @param[in] timeOut - for future use
 *
 * @return returns 0 on success, otherwise indicates failure
 */
SaSiError_t SaSi_PalMutexLock(SaSi_PalMutex *pMutexId, uint32_t timeOut)
{
    int rc = SASI_SUCCESS;

    SASI_UNUSED_PARAM(timeOut); // remove compilation warning
    rc = pthread_mutex_lock(pMutexId);
    if (rc != 0) {
        printf /* SASI_PAL_LOG_ERR */ ("pthread_mutex_lock failed 0x%x", rc);
        return SASI_FAIL;
    }
    return SASI_SUCCESS;
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
    int rc = SASI_SUCCESS;

    rc = pthread_mutex_unlock(pMutexId);
    if (rc != 0) {
        printf /* SASI_PAL_LOG_ERR */ ("pthread_mutex_unlock failed 0x%x", rc);
        return SASI_FAIL;
    }
    return SASI_SUCCESS;
}
