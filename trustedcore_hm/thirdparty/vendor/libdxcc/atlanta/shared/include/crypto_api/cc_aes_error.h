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

/*!
@file
@brief This file contains the definitions of the CryptoCell AES errors.
*/

#ifndef CC_AES_ERROR_H
#define CC_AES_ERROR_H

#include "cc_error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/

/* CC_AES_MODULE_ERROR_BASE - 0x00F00000 */
#define CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR     (CC_AES_MODULE_ERROR_BASE + 0x00UL)
#define CC_AES_INVALID_IV_OR_TWEAK_PTR_ERROR          (CC_AES_MODULE_ERROR_BASE + 0x01UL)
#define CC_AES_ILLEGAL_OPERATION_MODE_ERROR           (CC_AES_MODULE_ERROR_BASE + 0x02UL)
#define CC_AES_ILLEGAL_KEY_SIZE_ERROR                 (CC_AES_MODULE_ERROR_BASE + 0x03UL)
#define CC_AES_INVALID_KEY_POINTER_ERROR              (CC_AES_MODULE_ERROR_BASE + 0x04UL)
#define CC_AES_KEY_TYPE_NOT_SUPPORTED_ERROR           (CC_AES_MODULE_ERROR_BASE + 0x05UL)
#define CC_AES_INVALID_ENCRYPT_MODE_ERROR             (CC_AES_MODULE_ERROR_BASE + 0x06UL)
#define CC_AES_USER_CONTEXT_CORRUPTED_ERROR           (CC_AES_MODULE_ERROR_BASE + 0x07UL)
#define CC_AES_DATA_IN_POINTER_INVALID_ERROR          (CC_AES_MODULE_ERROR_BASE + 0x08UL)
#define CC_AES_DATA_OUT_POINTER_INVALID_ERROR         (CC_AES_MODULE_ERROR_BASE + 0x09UL)
#define CC_AES_DATA_IN_SIZE_ILLEGAL                   (CC_AES_MODULE_ERROR_BASE + 0x0AUL)
#define CC_AES_DATA_OUT_DATA_IN_OVERLAP_ERROR         (CC_AES_MODULE_ERROR_BASE + 0x0BUL)
#define CC_AES_DATA_IN_BUFFER_SIZE_ERROR              (CC_AES_MODULE_ERROR_BASE + 0x0CUL)
#define CC_AES_DATA_OUT_BUFFER_SIZE_ERROR             (CC_AES_MODULE_ERROR_BASE + 0x0DUL)
#define CC_AES_ILLEGAL_PADDING_TYPE_ERROR             (CC_AES_MODULE_ERROR_BASE + 0x0EUL)
#define CC_AES_INCORRECT_PADDING_ERROR                (CC_AES_MODULE_ERROR_BASE + 0x0FUL)
#define CC_AES_CORRUPTED_OUTPUT_ERROR                 (CC_AES_MODULE_ERROR_BASE + 0x10UL)
#define CC_AES_DATA_OUT_SIZE_POINTER_INVALID_ERROR    (CC_AES_MODULE_ERROR_BASE + 0x11UL)
#define CC_AES_DECRYPTION_NOT_ALLOWED_ON_THIS_MODE    (CC_AES_MODULE_ERROR_BASE + 0x12UL)

#define CC_AES_ADDITIONAL_BLOCK_NOT_PERMITTED_ERROR   (CC_AES_MODULE_ERROR_BASE + 0x15UL)
#define CC_AES_CTX_SIZES_ERROR   	                (CC_AES_MODULE_ERROR_BASE + 0x16UL)

#define CC_AES_ILLEGAL_PARAMS_ERROR               (CC_AES_MODULE_ERROR_BASE + 0x60UL)
#define CC_AES_CTR_ILLEGAL_BLOCK_OFFSET_ERROR     (CC_AES_MODULE_ERROR_BASE + 0x70UL)
#define CC_AES_CTR_ILLEGAL_COUNTER_ERROR          (CC_AES_MODULE_ERROR_BASE + 0x71UL)
#define CC_AES_IS_NOT_SUPPORTED                   (CC_AES_MODULE_ERROR_BASE + 0xFFUL)

/************************ Enums ********************************/

/************************ Typedefs  ****************************/

/************************ Structs  *****************************/

/************************ Public Variables *********************/

/************************ Public Functions *********************/

#ifdef __cplusplus
}
#endif

#endif /* #ifndef CC_AES_ERROR_H */
