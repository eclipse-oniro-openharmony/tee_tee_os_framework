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



#ifndef _CC_PAL_MEMMAP_H
#define _CC_PAL_MEMMAP_H


#ifdef __cplusplus
extern "C"
{
#endif


#include "cc_pal_types.h"
#include "cc_general_defs.h"

/*!
* @file
* @brief This file contains functions for memory mapping
*        None of the described functions check the input parameters so the behavior
*        of the APIs in illegal parameters case is dependent on the operating system behavior.
*/

/*----------------------------
      PUBLIC FUNCTIONS
-----------------------------------*/

/**
 * @brief This function purpose is to return the base virtual address that maps the
 *        base physical address
 *
 * @return Zero on success.
 * @return A non-zero value in case of failure.
 */
uint32_t CC_PalMemMap(CCDmaAddr_t physicalAddress, /*!< [in] Start physical address of the I/O range to be mapped. */
	              uint32_t mapSize,	  /*!< [in] Number of bytes that were mapped. */
		      uint32_t **ppVirtBuffAddr /*!< [out] Pointer to the base virtual address to which the physical pages were mapped. */ );


/**
 * @brief This function purpose is to Unmap a specified address range previously mapped
 *        by CC_PalMemMap.
 *
 * @return Zero on success.
 * @return A non-zero value in case of failure.
 */
uint32_t CC_PalMemUnMap(uint32_t *pVirtBuffAddr, /*!< [in] Pointer to the base virtual address to which the physical pages were mapped. */
	                uint32_t mapSize	   /*!< [in] Number of bytes that were mapped. */);

#ifdef __cplusplus
}
#endif
#endif


