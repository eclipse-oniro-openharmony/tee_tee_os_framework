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



#ifndef _CC_PAL_MEM_H
#define _CC_PAL_MEM_H


#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types.h"
#include "cc_pal_mem_plat.h"
#include "cc_pal_malloc_plat.h"

/*!
@file
@brief This file contains functions for memory operations. The functions implementations
*     are generally just wrappers to different operating system calls.
*     None of the described functions check the input parameters so the behavior
*     of the APIs in illegal parameters case is dependent on the operating system behavior.
*/


/*----------------------------
      PUBLIC FUNCTIONS
-----------------------------------*/

/**** ----- Memory Operations APIs ----- ****/

/*!
* @brief This function purpose is to compare between two given buffers according to given size.
*
* @return The return values is according to operating system return values.
*/


int32_t CC_PalMemCmp(	const void* aTarget, /*!< [in] The target buffer to compare. */
	                const void* aSource, /*!< [in] The Source buffer to compare to. */
		        size_t      aSize    /*!< [in] Number of bytes to compare. */);

/* Definition for MemCmp */
#define  CC_PalMemCmp    _CC_PalMemCmp


/*!
 * @brief This function purpose is to copy aSize bytes from source buffer to destination buffer.
 *
 * @return void.
 */
void CC_PalMemCopy(	const void* aDestination, /*!< [out] The destination buffer to copy bytes to. */
	                const void* aSource,	  /*!< [in] The Source buffer to copy from. */
		        size_t      aSize	  /*!< [in] Number of bytes to copy. */ );

/*!
 * @brief This function purpose is to copy aSize bytes from source buffer to destination buffer.
 * This function Supports overlapped buffers.
 *
 * @return void.
 */
void CC_PalMemMove(	const void* aDestination, /*!< [out] The destination buffer to copy bytes to. */
	              	const void* aSource,	  /*!< [in] The Source buffer to copy from. */
		        size_t      aSize	  /*!< [in] Number of bytes to copy. */);

/* Definition for MemCopy */
#define CC_PalMemCopy    _CC_PalMemCopy
#define CC_PalMemMove    _CC_PalMemMove


/*!
 * @brief This function purpose is to set aSize bytes in the given buffer with aChar.
 *
 * @return void.
 */
void CC_PalMemSet(	const void* aTarget, /*!< [out]  The target buffer to set. */
	                const uint8_t aChar, /*!< [in] The char to set into aTarget. */
		        size_t        aSize  /*!< [in] Number of bytes to set. */);

/* Definition for MemSet */
#define CC_PalMemSet(aTarget, aChar, aSize)   _CC_PalMemSet(aTarget, aChar, aSize)

/*!
 * @brief This function purpose is to set aSize bytes in the given buffer with zeroes.
 *
 * @return void.
 */
void CC_PalMemSetZero(	const void* aTarget, /*!< [out]  The target buffer to set. */
		        size_t      aSize    /*!< [in] Number of bytes to set. */);

#define CC_PalMemSetZero(aTarget, aSize)   _CC_PalMemSetZero(aTarget, aSize)

/**** ----- Memory Allocation APIs ----- ****/

/*!
 * @brief This function purpose is to allocate a memory buffer according to aSize.
 *
 *
 * @return The function returns a pointer to allocated buffer or NULL if allocation failed.
 */
void* CC_PalMemMalloc(size_t  aSize /*!< [in] Number of bytes to allocate. */);

/* Definition for MemMalloc */
#define CC_PalMemMalloc  _CC_PalMemMalloc

/*!
 * @brief This function purpose is to reallocate a memory buffer according to aNewSize.
 *        The content of the old buffer is moved to the new location.
 *
 * @return The function returns a pointer to the newly allocated buffer or NULL if allocation failed.
 */
void* CC_PalMemRealloc(  void* aBuffer, 	/*!< [in] Pointer to allocated buffer. */
                         size_t  aNewSize 	/*!< [in] Number of bytes to reallocate. */);

/* Definition for MemRealloc */
#define CC_PalMemRealloc  _CC_PalMemRealloc

/*!
 * @brief This function purpose is to free allocated buffer.
 *
 *
 * @return void.
 */
void CC_PalMemFree(void* aBuffer /*!< [in] Pointer to allocated buffer.*/);

/* Definition for MemFree */
#define CC_PalMemFree  _CC_PalMemFree

#ifdef __cplusplus
}
#endif

#endif


