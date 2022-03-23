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
@brief This file contains definitions that are used in the CryptoCell AES APIs.
*/

#ifndef CC_AES_DEFS_H
#define CC_AES_DEFS_H

#include "cc_pal_types.h"


#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/

/*! The size of the user's context prototype (see CCAesUserContext_t) in words. */
#define CC_AES_USER_CTX_SIZE_IN_WORDS 131		/*!< \internal In order to allow contiguous context the user context is doubled + 3 words for offset management */

/*! The AES block size in words. */
#define CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS 4
/*! The AES block size in bytes. */
#define CC_AES_BLOCK_SIZE_IN_BYTES  (CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS * sizeof(uint32_t))

/*! The size of the IV buffer in words. */
#define CC_AES_IV_SIZE_IN_WORDS   CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS
/*! The size of the IV buffer in bytes. */
#define CC_AES_IV_SIZE_IN_BYTES  (CC_AES_IV_SIZE_IN_WORDS * sizeof(uint32_t))

/*! The maximum size of the AES KEY in words. */
#define CC_AES_KEY_MAX_SIZE_IN_WORDS 16
/*! The maximum size of the AES KEY in bytes. */
#define CC_AES_KEY_MAX_SIZE_IN_BYTES (CC_AES_KEY_MAX_SIZE_IN_WORDS * sizeof(uint32_t))


#ifdef __cplusplus
}
#endif

#endif /* #ifndef CC_AES_DEFS_H */
