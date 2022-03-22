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

#ifndef _CC_HASH_ERROR_H
#define _CC_HASH_ERROR_H


#include "cc_error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains the definitions of the CryptoCell HASH errors.
*/




/************************ Defines ******************************/
/*HASH module on the CryptoCell layer base address - 0x00F00200*/
/* The CryptoCell HASH module errors */
#define CC_HASH_INVALID_USER_CONTEXT_POINTER_ERROR    	(CC_HASH_MODULE_ERROR_BASE + 0x0UL)
#define CC_HASH_ILLEGAL_OPERATION_MODE_ERROR          	(CC_HASH_MODULE_ERROR_BASE + 0x1UL)
#define CC_HASH_USER_CONTEXT_CORRUPTED_ERROR          	(CC_HASH_MODULE_ERROR_BASE + 0x2UL)
#define CC_HASH_DATA_IN_POINTER_INVALID_ERROR         	(CC_HASH_MODULE_ERROR_BASE + 0x3UL)
#define CC_HASH_DATA_SIZE_ILLEGAL                     	(CC_HASH_MODULE_ERROR_BASE + 0x4UL)
#define CC_HASH_INVALID_RESULT_BUFFER_POINTER_ERROR   	(CC_HASH_MODULE_ERROR_BASE + 0x5UL)
#define CC_HASH_DATA_SIZE_IS_ILLEGAL_FOR_CSI_ERROR    	(CC_HASH_MODULE_ERROR_BASE + 0x8UL)
#define CC_HASH_LAST_BLOCK_ALREADY_PROCESSED_ERROR	(CC_HASH_MODULE_ERROR_BASE + 0xCUL)
#define CC_HASH_ILLEGAL_PARAMS_ERROR 			(CC_HASH_MODULE_ERROR_BASE + 0xDUL)

#define CC_HASH_CTX_SIZES_ERROR   	                (CC_HASH_MODULE_ERROR_BASE + 0xEUL)

#define CC_HASH_IS_NOT_SUPPORTED                      	(CC_HASH_MODULE_ERROR_BASE + 0xFUL)



/************************ Enums ********************************/


/************************ Typedefs  ****************************/


/************************ Structs  ******************************/


/************************ Public Variables **********************/


/************************ Public Functions **********************/

#ifdef __cplusplus
}
#endif

#endif


