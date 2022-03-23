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

#ifndef  _CC_UTIL_DEFS_H
#define  _CC_UTIL_DEFS_H

/*!
@file
@brief This file contains CryptoCell Util general definitions.
*/


#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types_plat.h"
#include "cc_util_key_derivation_defs.h"


/******************************************************************************
*                        	DEFINITIONS
******************************************************************************/

#define CC_UTIL_AES_128BIT_SIZE	16  // same as CC_AES_128_BIT_KEY_SIZE
/*****************************************/
/* CMAC derive key definitions*/
/*****************************************/
#define CC_UTIL_CMAC_DERV_MIN_DATA_IN_SIZE	CC_UTIL_FIX_DATA_MIN_SIZE_IN_BYTES+2
#define CC_UTIL_CMAC_DERV_MAX_DATA_IN_SIZE	CC_UTIL_MAX_KDF_SIZE_IN_BYTES
#define CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES	0x10UL
#define CC_UTIL_AES_CMAC_RESULT_SIZE_IN_WORDS	(CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES/sizeof(uint32_t))

/*! Util Error type. */
typedef uint32_t CCUtilError_t;
/*! Defines the CMAC result buffer  - 16 bytes array. */
typedef uint8_t CCUtilAesCmacResult_t[CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES];


#ifdef __cplusplus
}
#endif

#endif /*_CC_UTIL_DEFS_H*/
