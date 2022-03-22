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
// #include <time.h>
#include "dx_pal_types.h"
#include "dx_pal_mutex.h"
#include "dx_pal_log.h"
// #include <stdio.h>

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
DxError_t DX_PAL_MutexCreate(DX_PAL_MUTEX *pMutexId)
{
    // int  rc = DX_SUCCESS;

    // rc = pthread_mutex_init(pMutexId, NULL);
    // if (rc != 0) {
    //    printf /* DX_PAL_LOG_ERR */("pthread_mutex_init failed 0x%x", rc);
    //    return DX_FAIL;
    // }
    return DX_SUCCESS;
}

/*
 * @brief This function purpose is to destroy a mutex
 *
 *
 * @param[in] pMutexId - pointer to Mutex handle
 *
 * @return returns 0 on success, otherwise indicates failure
 */
DxError_t DX_PAL_MutexDestroy(DX_PAL_MUTEX *pMutexId)
{
    // int  rc = DX_SUCCESS;

    // rc = pthread_mutex_destroy(pMutexId);
    // if (rc != 0) {
    //     printf /* DX_PAL_LOG_ERR */("pthread_mutex_destroy failed 0x%x", rc);
    //    return DX_FAIL;
    // }
    return DX_SUCCESS;
}

/*
 * @brief This function purpose is to Wait for Mutex with aTimeOut. aTimeOut is
 *        specified in milliseconds. (DX_INFINITE is blocking)
 *
 *
 * @param[in] pMutexId - pointer to Mutex handle
 * @param[in] timeOut - for future use
 *
 * @return returns 0 on success, otherwise indicates failure
 */
DxError_t DX_PAL_MutexLock(DX_PAL_MUTEX *pMutexId, uint32_t timeOut)
{
    // int  rc = DX_SUCCESS;

    // rc = pthread_mutex_lock(pMutexId);
    // if (rc != 0) {
    //    printf /* DX_PAL_LOG_ERR */("pthread_mutex_lock failed 0x%x", rc);
    //    return DX_FAIL;
    // }
    return DX_SUCCESS;
}

/*
 * @brief This function purpose is to release the mutex.
 *
 *
 * @param[in] pMutexId - pointer to Mutex handle
 *
 * @return returns 0 on success, otherwise indicates failure
 */
DxError_t DX_PAL_MutexUnlock(DX_PAL_MUTEX *pMutexId)
{
    // int  rc = DX_SUCCESS;

    // rc = pthread_mutex_unlock(pMutexId);
    // if (rc != 0) {
    //    printf /* DX_PAL_LOG_ERR */("pthread_mutex_unlock failed 0x%x", rc);
    //    return DX_FAIL;
    // }
    return DX_SUCCESS;
}
