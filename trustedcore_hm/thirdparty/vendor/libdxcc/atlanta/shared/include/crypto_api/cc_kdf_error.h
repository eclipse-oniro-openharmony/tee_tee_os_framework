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

#ifndef _CC_KDF_ERROR_H
#define _CC_KDF_ERROR_H

#include "cc_error.h"


#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains the definitions of the CryptoCell KDF errors.
 */


/************************ Defines *******************************/

/* The CryptoCell KDF module errors / base address - 0x00F01100*/
#define CC_KDF_INVALID_ARGUMENT_POINTER_ERROR			(CC_KDF_MODULE_ERROR_BASE + 0x0UL)
#define CC_KDF_INVALID_ARGUMENT_SIZE_ERROR			(CC_KDF_MODULE_ERROR_BASE + 0x1UL)
#define CC_KDF_INVALID_ARGUMENT_OPERATION_MODE_ERROR		(CC_KDF_MODULE_ERROR_BASE + 0x2UL)
#define CC_KDF_INVALID_ARGUMENT_HASH_MODE_ERROR			(CC_KDF_MODULE_ERROR_BASE + 0x3UL)
#define CC_KDF_INVALID_KEY_DERIVATION_MODE_ERROR              	(CC_KDF_MODULE_ERROR_BASE + 0x4UL)
#define CC_KDF_INVALID_SHARED_SECRET_VALUE_SIZE_ERROR         	(CC_KDF_MODULE_ERROR_BASE + 0x5UL)
#define CC_KDF_INVALID_OTHER_INFO_SIZE_ERROR                  	(CC_KDF_MODULE_ERROR_BASE + 0x6UL)
#define CC_KDF_INVALID_KEYING_DATA_SIZE_ERROR                 	(CC_KDF_MODULE_ERROR_BASE + 0x7UL)
#define CC_KDF_INVALID_ALGORITHM_ID_POINTER_ERROR             	(CC_KDF_MODULE_ERROR_BASE + 0x8UL)
#define CC_KDF_INVALID_ALGORITHM_ID_SIZE_ERROR                	(CC_KDF_MODULE_ERROR_BASE + 0x9UL)

#define CC_KDF_IS_NOT_SUPPORTED                               	(CC_KDF_MODULE_ERROR_BASE + 0xFFUL)

/************************ Enums *********************************/

/************************ Typedefs  *****************************/

/************************ Structs  ******************************/

/************************ Public Variables **********************/

/************************ Public Functions **********************/




#ifdef __cplusplus
}
#endif

#endif




