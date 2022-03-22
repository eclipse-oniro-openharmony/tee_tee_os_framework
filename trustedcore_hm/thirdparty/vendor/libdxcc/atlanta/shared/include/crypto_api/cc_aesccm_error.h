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

#ifndef _CC_AESCCM_ERROR_H
#define _CC_AESCCM_ERROR_H


#include "cc_error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains the definitions of the CryptoCell AESCCM errors.
*/

/************************ Defines ******************************/

/* The CryptoCell AESCCM module errors.
   CC_AESCCM_MODULE_ERROR_BASE = 0x00F01500 */
#define CC_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR     (CC_AESCCM_MODULE_ERROR_BASE + 0x00UL)
#define CC_AESCCM_ILLEGAL_KEY_SIZE_ERROR                 (CC_AESCCM_MODULE_ERROR_BASE + 0x01UL)
#define CC_AESCCM_INVALID_KEY_POINTER_ERROR              (CC_AESCCM_MODULE_ERROR_BASE + 0x02UL)
#define CC_AESCCM_INVALID_ENCRYPT_MODE_ERROR             (CC_AESCCM_MODULE_ERROR_BASE + 0x03UL)
#define CC_AESCCM_USER_CONTEXT_CORRUPTED_ERROR           (CC_AESCCM_MODULE_ERROR_BASE + 0x04UL)
#define CC_AESCCM_DATA_IN_POINTER_INVALID_ERROR          (CC_AESCCM_MODULE_ERROR_BASE + 0x05UL)
#define CC_AESCCM_DATA_OUT_POINTER_INVALID_ERROR         (CC_AESCCM_MODULE_ERROR_BASE + 0x06UL)
#define CC_AESCCM_DATA_IN_SIZE_ILLEGAL                   (CC_AESCCM_MODULE_ERROR_BASE + 0x07UL)
#define CC_AESCCM_DATA_OUT_DATA_IN_OVERLAP_ERROR         (CC_AESCCM_MODULE_ERROR_BASE + 0x08UL)
#define CC_AESCCM_DATA_OUT_SIZE_INVALID_ERROR            (CC_AESCCM_MODULE_ERROR_BASE + 0x09UL)
#define CC_AESCCM_ADDITIONAL_BLOCK_NOT_PERMITTED_ERROR   (CC_AESCCM_MODULE_ERROR_BASE + 0x0AUL)
#define CC_AESCCM_ILLEGAL_DMA_BUFF_TYPE_ERROR        	 (CC_AESCCM_MODULE_ERROR_BASE + 0x0BUL)
#define CC_AESCCM_ILLEGAL_PARAMETER_SIZE_ERROR           (CC_AESCCM_MODULE_ERROR_BASE + 0x0CUL)
#define CC_AESCCM_ILLEGAL_PARAMETER_PTR_ERROR            (CC_AESCCM_MODULE_ERROR_BASE + 0x0DUL)
#define CC_AESCCM_ILLEGAL_DATA_TYPE_ERROR                (CC_AESCCM_MODULE_ERROR_BASE + 0x0EUL)
#define CC_AESCCM_CCM_MAC_INVALID_ERROR                  (CC_AESCCM_MODULE_ERROR_BASE + 0x0FUL)
#define CC_AESCCM_LAST_BLOCK_NOT_PERMITTED_ERROR         (CC_AESCCM_MODULE_ERROR_BASE + 0x10UL)
#define CC_AESCCM_ILLEGAL_PARAMETER_ERROR                (CC_AESCCM_MODULE_ERROR_BASE + 0x11UL)
#define CC_AESCCM_NOT_ALL_ADATA_WAS_PROCESSED_ERROR      (CC_AESCCM_MODULE_ERROR_BASE + 0x13UL)
#define CC_AESCCM_NOT_ALL_DATA_WAS_PROCESSED_ERROR       (CC_AESCCM_MODULE_ERROR_BASE + 0x14UL)
#define CC_AESCCM_ADATA_WAS_PROCESSED_ERROR      	 (CC_AESCCM_MODULE_ERROR_BASE + 0x15UL)
#define CC_AESCCM_ILLEGAL_NONCE_SIZE_ERROR		 (CC_AESCCM_MODULE_ERROR_BASE + 0x16UL)
#define CC_AESCCM_ILLEGAL_TAG_SIZE_ERROR		 (CC_AESCCM_MODULE_ERROR_BASE + 0x17UL)

#define CC_AESCCM_CTX_SIZES_ERROR		   	 (CC_AESCCM_MODULE_ERROR_BASE + 0x28UL)
#define CC_AESCCM_ILLEGAL_PARAMS_ERROR		   	 (CC_AESCCM_MODULE_ERROR_BASE + 0x29UL)
#define CC_AESCCM_IS_NOT_SUPPORTED                       (CC_AESCCM_MODULE_ERROR_BASE + 0xFFUL)

/************************ Enums ********************************/

/************************ Typedefs  ****************************/

/************************ Structs  *****************************/

/************************ Public Variables *********************/

/************************ Public Functions *********************/

#ifdef __cplusplus
}
#endif

#endif /* _CC_AESCCM_ERROR_H */


