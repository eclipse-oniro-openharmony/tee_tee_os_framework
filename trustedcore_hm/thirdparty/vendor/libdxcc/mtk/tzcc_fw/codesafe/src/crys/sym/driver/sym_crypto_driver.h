/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SEP_SYM_CRYPTO_DRIVER_H
#define SEP_SYM_CRYPTO_DRIVER_H

#include "cc_plat.h"
#include "dma_buffer.h"
#include "hw_queue_defs.h"
#include "ssi_compiler.h"
#include "ssi_crypto_ctx.h"

/* *****************************************************************************
 *                DEFINITIONS
 * *************************************************************************** */

/* *****************************************************************************
 *                MACROS
 * *************************************************************************** */

/* *****************************************************************************
 *                TYPE DEFINITIONS
 * *************************************************************************** */
#ifndef ZERO_BLOCK_DEFINED
extern const uint32_t ZeroBlock[SEP_AES_BLOCK_SIZE_WORDS];
#endif

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */
/* !
 * Initializes sym. driver resources.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverInit(void) SASI_ICACHE_FUNCTION;

/* !
 * Delete sym. driver resources.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverFini(void) SASI_ICACHE_FUNCTION;

/* !
 * This function is called from the SW queue manager which passes the
 * related context. The function casts the context buffer and diverts
 * to the specific SaSi Init API according to the cipher algorithm that
 * associated in the given context. It is also prepare the necessary
 * firmware private context parameters that are require for the crypto
 * operation, for example, computation of the AES-MAC k1, k2, k3 values.
 * The API has no affect on the user data buffers.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverDispatchInit(DxSramAddr_t ctxAddr);

/* !
 * This function is called from the SW queue manager in order to process
 * a symmetric crypto operation on the user data buffers.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverDispatchProcess(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

/* !
 * This function is called from the SW queue manager in order to complete
 * a crypto operation. The SW queue manager calls this API when the
 * "Process" bit "0x2" is set in the SW descriptor header. This function
 * may be invoked after "DispatchDriverProcess" or "DispatchDriverInit" with any
 * number of IN/OUT MLLI tables.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in head of file.
 */
int SymDriverDispatchFinalize(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

#endif /* SEP_SYM_CRYPTO_DRIVER_H */
