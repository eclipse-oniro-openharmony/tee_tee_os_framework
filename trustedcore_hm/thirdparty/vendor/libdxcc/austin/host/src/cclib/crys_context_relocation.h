/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

/* ! \file crys_context_relocation.h
 * Handle relocation of crypto context in the context buffer given
 * by the user to assure it does not cross a page boundary
 */

#ifndef _CRYS_CONTEXT_RELOCATION_H_
#define _CRYS_CONTEXT_RELOCATION_H_

#define DX_CTX_BUFF_PROPS_SIZE_BYTES 12

/* !
 * Initialize the context offset for a new buffer given to INIT phase
 *
 * \param bufferStart The address of the context buffer given by the user
 * \param bufferSize The size of the user buffer in bytes
 * \param contextSize The required size (in bytes) of the context
 *
 * \return The address of the context within the buffer
 */
void *DX_InitUserCtxLocation(void *bufferStart, unsigned long bufferSize, unsigned long contextSize);

/* !
 * Return the context address in the given buffer
 * If previous context offset is now crossing a page the context data
 * would be moved to a good location.
 *
 * \param bufferStart The address of the context buffer given by the user
 *
 * \return The address of the context within the buffer
 */
void *DX_GetUserCtxLocation(void *bufferStart, unsigned long bufferSize);

#endif /* _CRYS_CONTEXT_RELOCATION_H_ */
