/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SEP_HMAC_H
#define SEP_HMAC_H

#include "cc_plat.h"
#include "mlli.h"
#include "ssi_crypto_ctx.h"
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
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
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
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
int FinalizeHmac(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

#endif /* SEP_HMAC_H */
