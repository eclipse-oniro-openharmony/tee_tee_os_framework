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

#ifndef  _CC_UTIL_CMAC_H
#define  _CC_UTIL_CMAC_H

#include "cc_util_int_defs.h"

/******************************************************************************
*                        	DEFINITIONS
******************************************************************************/


/*!
 * This function is used to generate bytes stream for key derivation purposes.
 * The function gets an input data and can use use one of the following keys: KDR/Session/userKey.
 *
 * @param[in] aesKeyType 	- UTIL_USER_KEY / UTIL_ROOT_KEY / UTIL_SESSION_KEY.
 * @param[in] pUserKey		- A pointer to the user's key buffer (case of CC_UTIL_USER_KEY).
 * @param[in] pDataIn 		- A pointer to input buffer.
 * @param[in] dataInSize 	- Size of data in bytes.
 * @param[out] pCmacResult 	- A pointer to output buffer 16 bytes array.
 *
 * @return CC_UTIL_OK on success, otherwise failure
 *
 */
CCUtilError_t UtilCmacDeriveKey(UtilKeyType_t    	keyType,
				CCAesUserKeyData_t     	*pUserKey,
				uint8_t			*pDataIn,
				size_t                	dataInSize,
				CCUtilAesCmacResult_t   	pCmacResult);


#endif /* _CC_UTIL_CMAC_H */
