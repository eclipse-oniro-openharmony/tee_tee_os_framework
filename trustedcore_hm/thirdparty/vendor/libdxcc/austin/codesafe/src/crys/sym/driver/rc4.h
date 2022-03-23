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

#ifndef SEP_RC4_H
#define SEP_RC4_H

#include "sep_ctx.h"
#include "dma_buffer.h"

/* *****************************************************************************
 *                DEFINITIONS
 * *************************************************************************** */

/* *****************************************************************************
 *                MACROS
 * *************************************************************************** */

/* *****************************************************************************
 *                TYPE DEFINITIONS
 * *************************************************************************** */

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */
/* !
 * This function is used to initialize the RC4 machine to perform the RC4
 * operations. This should be the first function called. It initializes
 * the permutation in the "S" array.
 *
 * \param pCtx A pointer to the context buffer in SRAM.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int InitRc4(struct sep_ctx_rc4 *pCtx);

/* !
 * This function is used to process a block(s) of data on RC4 machine.
 * This function may be called after the "InitRc4" function.
 *
 * \param pCtx A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int ProcessRc4(struct sep_ctx_rc4 *pCtx, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

/* !
 * This function is used as finish the RC4 operation.
 * The function may either be called after "InitRc4" or "ProcessRc4".
 *
 * \param pCtx A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int FinalizeRc4(struct sep_ctx_rc4 *pCtx, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

#endif /* SEP_RC4_H */
