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

/*! \file cc_context_relocation.h
 * Handle relocation of crypto context in the context buffer given
 * by the user to assure it does not cross a page boundary
 */

#ifndef _CC_CONTEXT_RELOCATION_H_
#define _CC_CONTEXT_RELOCATION_H_

#define CC_CTX_BUFF_PROPS_SIZE_BYTES	12


/*!
 * Initialize the context offset for a new buffer given to INIT phase
 *
 * \param bufferStart The address of the context buffer given by the user
 * \param bufferSize The size of the user buffer in bytes
 * \param contextSize The required size (in bytes) of the context
 *
 * \return The address of the context within the buffer
 */
void *RcInitUserCtxLocation(void *bufferStart,
			     unsigned long bufferSize,
			     unsigned long contextSize);

/*!
 * Return the context address in the given buffer
 * If previous context offset is now crossing a page the context data
 * would be moved to a good location.
 *
 * \param bufferStart The address of the context buffer given by the user
 *
 * \return The address of the context within the buffer
 */
void *RcGetUserCtxLocation(void *bufferStart);

/*
 * Just return the context address in the given buffer. Not relocation
 * \param bufferStart The address of the context buffer given by the user
 *
 * \return The address of the context within the buffer
 */
void *GetUserCtxLocation(void *bufferStart);

#endif /*_CC_CONTEXT_RELOCATION_H_*/
