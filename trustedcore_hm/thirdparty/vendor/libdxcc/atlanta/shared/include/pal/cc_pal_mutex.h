/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/


#ifndef _CC_PAL_MUTEX_H
#define _CC_PAL_MUTEX_H

#include "cc_pal_mutex_plat.h"
#include "cc_pal_types_plat.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
* @file
* @brief This file contains functions for resource management (mutex operations).
*        The functions implementations are generally just wrappers to different operating system calls.
*        None of the described functions check the input parameters so the behavior
*        of the APIs in illegal parameters case is dependent on the operating system behavior.
*
*/




/*----------------------------
      PUBLIC FUNCTIONS
-----------------------------------*/

/**
 * @brief This function purpose is to create a mutex.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
CCError_t CC_PalMutexCreate(CC_PalMutex *pMutexId /*!< [out] Pointer to created mutex handle. */);


/**
 * @brief This function purpose is to destroy a mutex.
 *
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
CCError_t CC_PalMutexDestroy(CC_PalMutex *pMutexId /*!< [in] Pointer to mutex handle. */);


/**
 * @brief This function purpose is to Wait for Mutex with aTimeOut. aTimeOut is
 *        specified in milliseconds (CC_INFINITE is blocking).
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
CCError_t CC_PalMutexLock(CC_PalMutex *pMutexId, /*!< [in] Pointer to Mutex handle. */
			    uint32_t aTimeOut	/*!< [in] Timeout in mSec, or CC_INFINITE. */);


/**
 * @brief This function purpose is to release the mutex.
 *
 * @return Zero on success.
 * @return A non-zero value on failure.
 */
CCError_t CC_PalMutexUnlock(CC_PalMutex *pMutexId/*!< [in] Pointer to Mutex handle. */);





#ifdef __cplusplus
}
#endif

#endif


