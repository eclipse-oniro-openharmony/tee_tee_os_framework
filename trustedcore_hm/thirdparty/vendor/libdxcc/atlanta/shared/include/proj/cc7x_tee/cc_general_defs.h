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

#ifndef _CC_GENERAL_DEFS_H
#define _CC_GENERAL_DEFS_H

/*!
@file
@brief This file contains general definitions.
*/

#ifdef __cplusplus
extern "C"
{
#endif

/* general definitions */
/*-------------------------*/
#define CC_AES_KDR_MAX_SIZE_BYTES	32
#define CC_AES_KDR_MAX_SIZE_WORDS	(CC_AES_KDR_MAX_SIZE_BYTES/sizeof(uint32_t))


/* Life cycle state definitions */
#define CC_LCS_CHIP_MANUFACTURE_LCS		0x0 /*!< Life cycle CM value. */
#define CC_LCS_DEVICE_MANUFACTURE_LCS		0x1 /*!< Life cycle DM value. */
#define CC_LCS_SECURITY_DISABLED_LCS		0x3 /*!< Life cycle security disabled value. */
#define CC_LCS_SECURE_LCS			0x5 /*!< Life cycle secure value. */
#define CC_LCS_RMA_LCS				0x7 /*!< Life cycle RMA value. */

/**
 * Address types within CC
 */
typedef uint32_t CCSramAddr_t;
typedef uint64_t CCDmaAddr_t;

#ifdef __cplusplus
}
#endif

#endif



