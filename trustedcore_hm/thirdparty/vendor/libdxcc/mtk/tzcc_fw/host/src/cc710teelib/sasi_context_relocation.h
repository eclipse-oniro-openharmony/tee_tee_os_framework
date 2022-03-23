/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ! \file sasi_context_relocation.h
 * Handle relocation of crypto context in the context buffer given
 * by the user to assure it does not cross a page boundary
 */

#ifndef _SaSi_CONTEXT_RELOCATION_H_
#define _SaSi_CONTEXT_RELOCATION_H_

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
void *SaSi_InitUserCtxLocation(void *bufferStart, unsigned long bufferSize, unsigned long contextSize);

/* !
 * Return the context address in the given buffer
 * If previous context offset is now crossing a page the context data
 * would be moved to a good location.
 *
 * \param bufferStart The address of the context buffer given by the user
 *
 * \return The address of the context within the buffer
 */
void *SaSi_GetUserCtxLocation(void *bufferStart);

#endif /* _SaSi_CONTEXT_RELOCATION_H_ */
