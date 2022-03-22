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

#ifndef  _CC_UTIL_ERROR_H
#define  _CC_UTIL_ERROR_H

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains the definitions of the UTIL module errors.
*/

/***********************/
/* Util return codes   */
/***********************/

#define CC_UTIL_OK		0x00UL

#define CC_UTIL_MODULE_ERROR_BASE 0x80000000

#define CC_UTIL_INVALID_KEY_TYPE             		(CC_UTIL_MODULE_ERROR_BASE + 0x00UL)
#define CC_UTIL_DATA_IN_POINTER_INVALID_ERROR		(CC_UTIL_MODULE_ERROR_BASE + 0x01UL)
#define CC_UTIL_DATA_IN_SIZE_INVALID_ERROR		(CC_UTIL_MODULE_ERROR_BASE + 0x02UL)
#define CC_UTIL_DATA_OUT_POINTER_INVALID_ERROR		(CC_UTIL_MODULE_ERROR_BASE + 0x03UL)
#define CC_UTIL_DATA_OUT_SIZE_INVALID_ERROR		(CC_UTIL_MODULE_ERROR_BASE + 0x04UL)
#define CC_UTIL_FATAL_ERROR				(CC_UTIL_MODULE_ERROR_BASE + 0x05UL)
#define CC_UTIL_ILLEGAL_PARAMS_ERROR			(CC_UTIL_MODULE_ERROR_BASE + 0x06UL)
#define CC_UTIL_BAD_ADDR_ERROR				(CC_UTIL_MODULE_ERROR_BASE + 0x07UL)
#define CC_UTIL_EK_DOMAIN_INVALID_ERROR			(CC_UTIL_MODULE_ERROR_BASE + 0x08UL)
#define CC_UTIL_KDR_INVALID_ERROR             		(CC_UTIL_MODULE_ERROR_BASE + 0x09UL)
#define CC_UTIL_LCS_INVALID_ERROR            		(CC_UTIL_MODULE_ERROR_BASE + 0x0AUL)
#define CC_UTIL_SESSION_KEY_ERROR            		(CC_UTIL_MODULE_ERROR_BASE + 0x0BUL)
#define CC_UTIL_MUTEX_ERROR            			(CC_UTIL_MODULE_ERROR_BASE + 0x0CUL)
#define CC_UTIL_INVALID_USER_KEY_SIZE  			(CC_UTIL_MODULE_ERROR_BASE + 0x0DUL)
#define CC_UTIL_ILLEGAL_LCS_FOR_OPERATION_ERR		(CC_UTIL_MODULE_ERROR_BASE + 0x0EUL)

#ifdef __cplusplus
}
#endif

#endif /*_CC_UTIL_ERROR_H*/
