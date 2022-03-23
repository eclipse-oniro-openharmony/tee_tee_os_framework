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

#ifndef _CC_SEC_DEFS_H
#define _CC_SEC_DEFS_H

/*!
@file
@brief This file contains general hash definitions and types.
*/


#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types.h"

/*! The hashblock size in words. */
#define HASH_BLOCK_SIZE_IN_WORDS             16
/*! The hash - SHA2 results in words. */
#define HASH_RESULT_SIZE_IN_WORDS            8
#define HASH_RESULT_SIZE_IN_BYTES            32

/*! Definition for hash result array. */
typedef uint32_t CCHashResult_t[HASH_RESULT_SIZE_IN_WORDS];



#ifdef __cplusplus
}
#endif

#endif



