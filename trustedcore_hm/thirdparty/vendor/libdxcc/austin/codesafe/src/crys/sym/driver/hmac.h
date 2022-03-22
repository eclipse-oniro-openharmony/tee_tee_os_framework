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

#ifndef SEP_HMAC_H
#define SEP_HMAC_H

#include "cc_plat.h"
#include "mlli.h"
#include "sep_ctx.h"
#include "dma_buffer.h"

/* *****************************************************************************
 *                DEFINITIONS
 * *************************************************************************** */

/* *****************************************************************************
 *                MACROS
 * *************************************************************************** */
/* the MAC key IPAD and OPAD bytes */
#define MAC_KEY_IPAD_BYTE 0x36
#define MAC_KEY_OPAD_BYTE 0x5C

/* *****************************************************************************
 *                TYPE DEFINITIONS
 * *************************************************************************** */

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */

/* !
 * This function is used to initialize the HMAC machine to perform the HMAC
 * operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int InitHmac(DxSramAddr_t ctxAddr);

/* ***************************************************************************** */
/* ***************************************************************************** */
/* !! we do not implement "ProcessHmac" since it directly calls ProcessHash     */
/* ***************************************************************************** */
/* ***************************************************************************** */

/* !
 * This function is used as finish operation of the HMAC machine.
 * The function may be called after "InitHmac".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int FinalizeHmac(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

#endif /* SEP_HMAC_H */
