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

#ifndef _CC_HASH_DEFS_H
#define _CC_HASH_DEFS_H

/*!
@file
@brief This file contains HASH definitions.
*/

#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/

/*! The size of user's context prototype (see CCHashUserContext_t) in words. */
/* In order to allow contiguous context the user context is doubled + 3 words for management */
/*
CC_HASH_USER_CTX_SIZE_IN_WORDS = (2 * (<sizeof drv_ctx_hash in words> + <sizeof CCHashPrivateContext_t in words>)) + 3 (management) = 197
* <sizeof drv_ctx_hash in words> = CC_DRV_CTX_SIZE_WORDS(64)
* <sizeof CCHashPrivateContext_t in words> = CC_HASH_SHA512_BLOCK_SIZE_IN_WORDS(32) + <size of uint32_t in words>(1)
*/
#define CC_HASH_USER_CTX_SIZE_IN_WORDS 197


#ifdef __cplusplus
}
#endif

#endif
