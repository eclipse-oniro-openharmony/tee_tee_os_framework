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


#ifndef _CC_DH_ERROR_H
#define _CC_DH_ERROR_H


#include "cc_error.h"


#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains error codes definitions for CryptoCell DH module.
*/
/************************ Defines ******************************/
/* DH module on the CryptoCell layer base address - 0x00F00500 */
/* The CryptoCell DH module errors */
#define CC_DH_INVALID_ARGUMENT_POINTER_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x0UL)
#define CC_DH_INVALID_ARGUMENT_SIZE_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x1UL)
#define CC_DH_INVALID_ARGUMENT_OPERATION_MODE_ERROR		(CC_DH_MODULE_ERROR_BASE + 0x2UL)
#define CC_DH_INVALID_ARGUMENT_HASH_MODE_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x3UL)

/*the derived secret key size needed is wrong*/
#define CC_DH_SECRET_KEYING_DATA_SIZE_ILLEGAL_ERROR		(CC_DH_MODULE_ERROR_BASE + 0x4UL)
#define CC_DH_INVALID_L_ARGUMENT_ERROR				(CC_DH_MODULE_ERROR_BASE + 0x5UL)
#define CC_DH_ARGUMENT_PRIME_SMALLER_THAN_GENERATOR_ERROR	(CC_DH_MODULE_ERROR_BASE + 0x6UL)
#define CC_DH_ARGUMENT_GENERATOR_SMALLER_THAN_ZERO_ERROR    	(CC_DH_MODULE_ERROR_BASE + 0x7UL)
#define CC_DH_ARGUMENT_PRV_SIZE_ERROR				(CC_DH_MODULE_ERROR_BASE + 0x8UL)
#define CC_DH_ARGUMENT_BUFFER_SIZE_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x9UL)
#define CC_DH_INVALID_SHARED_SECRET_VALUE_ERROR			(CC_DH_MODULE_ERROR_BASE + 0xAUL)
#define CC_DH_IS_NOT_SUPPORTED					(CC_DH_MODULE_ERROR_BASE + 0xFUL)

#define CC_DH_X942_HYBRID_SIZE1_BUFFER_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x15UL)

/*The requested derived secret key size is invalid*/
#define CC_DH_SECRET_KEY_SIZE_NEEDED_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x16UL)
#define CC_DH_SECRET_KEY_SIZE_OUTPUT_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x17UL)
#define CC_DH_OTHERINFO_SIZE_ERROR                            	(CC_DH_MODULE_ERROR_BASE + 0x18UL)

/* DH domain and key generation and checking errors */
#define CC_DH_INVALID_MODULUS_SIZE_ERROR			(CC_DH_MODULE_ERROR_BASE + 0x20UL)
#define CC_DH_INVALID_ORDER_SIZE_ERROR				(CC_DH_MODULE_ERROR_BASE + 0x21UL)
#define CC_DH_INVALID_SEED_SIZE_ERROR  				(CC_DH_MODULE_ERROR_BASE + 0x22UL)
#define CC_DH_INVALID_J_FACTOR_PTR_OR_SIZE_ERROR 		(CC_DH_MODULE_ERROR_BASE + 0x23UL)
#define CC_DH_INVALID_GENERATOR_PTR_OR_SIZE_ERROR 		(CC_DH_MODULE_ERROR_BASE + 0x24UL)

#define CC_DH_CHECK_DOMAIN_PRIMES_NOT_VALID_ERROR         	(CC_DH_MODULE_ERROR_BASE + 0x25UL)
#define CC_DH_CHECK_DOMAIN_GENERATOR_NOT_VALID_ERROR         	(CC_DH_MODULE_ERROR_BASE + 0x26UL)
#define CC_DH_INVALID_PUBLIC_KEY_SIZE_ERROR                 	(CC_DH_MODULE_ERROR_BASE + 0x27UL)
#define CC_DH_CHECK_PUB_KEY_NOT_VALID_ERROR                 	(CC_DH_MODULE_ERROR_BASE + 0x28UL)
#define CC_DH_CHECK_GENERATOR_SIZE_OR_PTR_NOT_VALID_ERROR    	(CC_DH_MODULE_ERROR_BASE + 0x29UL)
#define CC_DH_CHECK_SEED_SIZE_OR_PTR_NOT_VALID_ERROR          	(CC_DH_MODULE_ERROR_BASE + 0x2AUL)
#define CC_DH_CHECK_GENERATOR_NOT_VALID_ERROR               	(CC_DH_MODULE_ERROR_BASE + 0x2BUL)
#define CC_DH_PRIME_P_GENERATION_FAILURE_ERROR               	(CC_DH_MODULE_ERROR_BASE + 0x2CUL)
#define CC_DH_INVALID_PUBLIC_KEY_ERROR                    	(CC_DH_MODULE_ERROR_BASE + 0x2DUL)
#define CC_DH_PASSED_INVALID_SEED_ERROR  	            	(CC_DH_MODULE_ERROR_BASE + 0x2EUL)



/************************ Enums ********************************/


/************************ Typedefs  ****************************/


/************************ Structs  ******************************/


/************************ Public Variables **********************/


/************************ Public Functions **********************/




#ifdef __cplusplus
}
#endif

#endif

