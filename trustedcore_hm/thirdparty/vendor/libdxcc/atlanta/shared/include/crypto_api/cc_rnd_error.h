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


#ifndef _CC_RND_ERROR_H
#define _CC_RND_ERROR_H

#include "cc_error.h"

#ifdef __cplusplus
extern "C"
{
#endif


/*!
@file
@brief This file contains the definitions of the CryptoCell RND errors.
*/


/************************ Defines ******************************/
/* RND module on the CryptoCell layer base address - 0x00F00C00 */

#define CC_RND_DATA_OUT_POINTER_INVALID_ERROR        	(CC_RND_MODULE_ERROR_BASE + 0x0UL)
#define CC_RND_CAN_NOT_GENERATE_RAND_IN_RANGE        	(CC_RND_MODULE_ERROR_BASE + 0x1UL)
#define CC_RND_CPRNG_TEST_FAIL_ERROR		       	(CC_RND_MODULE_ERROR_BASE + 0x2UL)
#define CC_RND_ADDITIONAL_INPUT_BUFFER_NULL	       	(CC_RND_MODULE_ERROR_BASE + 0x3UL)
#define CC_RND_ADDITIONAL_INPUT_SIZE_ERROR	       	(CC_RND_MODULE_ERROR_BASE + 0x4UL)
#define CC_RND_DATA_SIZE_OVERFLOW_ERROR	       		(CC_RND_MODULE_ERROR_BASE + 0x5UL)
#define CC_RND_VECTOR_SIZE_ERROR			(CC_RND_MODULE_ERROR_BASE + 0x6UL)
#define CC_RND_RESEED_COUNTER_OVERFLOW_ERROR		(CC_RND_MODULE_ERROR_BASE + 0x7UL)
#define CC_RND_INSTANTIATION_NOT_DONE_ERROR		(CC_RND_MODULE_ERROR_BASE + 0x8UL)
#define CC_RND_TRNG_LOSS_SAMPLES_ERROR               	(CC_RND_MODULE_ERROR_BASE + 0x9UL)
#define CC_RND_TRNG_TIME_EXCEED_ERROR         		(CC_RND_MODULE_ERROR_BASE + 0xAUL)
#define CC_RND_TRNG_LOSS_SAMPLES_AND_TIME_EXCEED_ERROR 	(CC_RND_MODULE_ERROR_BASE + 0xBUL)
#define CC_RND_IS_KAT_MODE_ERROR                     	(CC_RND_MODULE_ERROR_BASE + 0xCUL)
#define CC_RND_OPERATION_IS_NOT_SUPPORTED_ERROR      	(CC_RND_MODULE_ERROR_BASE + 0xDUL)
#define CC_RND_STATE_VALIDATION_TAG_ERROR            	(CC_RND_MODULE_ERROR_BASE + 0xEUL)

#define CC_RND_IS_NOT_SUPPORTED                      	(CC_RND_MODULE_ERROR_BASE + 0xFUL)


#define CC_RND_GEN_VECTOR_FUNC_ERROR		        (CC_RND_MODULE_ERROR_BASE + 0x14UL)

#define CC_RND_WORK_BUFFER_PTR_INVALID_ERROR          	(CC_RND_MODULE_ERROR_BASE + 0x20UL)
#define CC_RND_ILLEGAL_AES_KEY_SIZE_ERROR             	(CC_RND_MODULE_ERROR_BASE + 0x21UL)
#define CC_RND_ILLEGAL_DATA_PTR_ERROR                 	(CC_RND_MODULE_ERROR_BASE + 0x22UL)
#define CC_RND_ILLEGAL_DATA_SIZE_ERROR                	(CC_RND_MODULE_ERROR_BASE + 0x23UL)
#define CC_RND_ILLEGAL_PARAMETER_ERROR                	(CC_RND_MODULE_ERROR_BASE + 0x24UL)
#define CC_RND_STATE_PTR_INVALID_ERROR                	(CC_RND_MODULE_ERROR_BASE + 0x25UL)
#define CC_RND_TRNG_ERRORS_ERROR                      	(CC_RND_MODULE_ERROR_BASE + 0x26UL)
#define CC_RND_CONTEXT_PTR_INVALID_ERROR              	(CC_RND_MODULE_ERROR_BASE + 0x27UL)

#define CC_RND_VECTOR_OUT_PTR_ERROR                   	(CC_RND_MODULE_ERROR_BASE + 0x30UL)
#define CC_RND_VECTOR_OUT_SIZE_ERROR			(CC_RND_MODULE_ERROR_BASE + 0x31UL)
#define CC_RND_MAX_VECTOR_IS_TOO_SMALL_ERROR		(CC_RND_MODULE_ERROR_BASE + 0x32UL)
#define CC_RND_KAT_DATA_PARAMS_ERROR                 	(CC_RND_MODULE_ERROR_BASE + 0x33UL)
#define CC_RND_TRNG_KAT_NOT_SUPPORTED_ERROR         	(CC_RND_MODULE_ERROR_BASE + 0x34UL)
#define CC_RND_SRAM_NOT_SUPPORTED_ERROR              	(CC_RND_MODULE_ERROR_BASE + 0x35UL)


/************************ Enums ********************************/


/************************ Typedefs  ****************************/


/************************ Structs  ******************************/


/************************ Public Variables **********************/


/************************ Public Functions **********************/

#ifdef __cplusplus
}
#endif

#endif


