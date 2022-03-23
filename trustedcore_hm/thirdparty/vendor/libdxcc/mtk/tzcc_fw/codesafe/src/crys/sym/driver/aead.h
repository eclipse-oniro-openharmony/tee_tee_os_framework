/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SEP_AEAD_H
#define SEP_AEAD_H

#include "mlli.h"
#include "dma_buffer.h"

/* *****************************************************************************
 *                DEFINITIONS
 * *************************************************************************** */

/* *****************************************************************************
 *                MACROS
 * *************************************************************************** */

/* !
  Set the internal machine work mode according to the given
  crypto direction
*/
#define SEP_AEAD_CCM_SET_INTERNAL_MODE(direction) \
    ((direction) == SEP_CRYPTO_DIRECTION_ENCRYPT ? SEP_AEAD_MODE_CCM_PE : SEP_AEAD_MODE_CCM_PD)

/* *****************************************************************************
 *                ENUMS
 * *************************************************************************** */
typedef enum SepAeadCcmMode {
    SEP_AEAD_MODE_NULL_MODE  = -1,
    SEP_AEAD_MODE_CCM_A      = 8,
    SEP_AEAD_MODE_CCM_PE     = 9,
    SEP_AEAD_MODE_CCM_PD     = 10,
    SEP_AEAD_MODE_RESERVE32B = INT32_MAX,
} SepAeadCcmMode_e;

typedef enum SepAeadCcmFlow {
    SEP_AEAD_FLOW_NULL = 0,
    SEP_AEAD_FLOW_ADATA_INIT,
    SEP_AEAD_FLOW_ADATA_PROCESS,
    SEP_AEAD_FLOW_TEXT_DATA_INIT,
    SEP_AEAD_FLOW_TEXT_DATA_PROCESS,
    SEP_AEAD_FLOW_RESERVE32B = INT32_MAX,
} SepAeadCcmFlow_e;

/* *****************************************************************************
 *                TYPE DEFINITIONS
 * *************************************************************************** */
typedef struct SepAeadPrivateContext {
    uint32_t internalMode;                /* auth/encrypt/decrypt modes */
    uint32_t q;                           /* an element of {2, 3, 4, 5, 6, 7, 8}; */
    uint32_t headerRemainingBytes;        /* associated data remaining bytes */
    SepAeadCcmFlow_e nextProcessingState; /* points to the next machine state */
} SepAeadPrivateContext_s;

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */
/* !
 * This function is used to initialize the AES machine to perform
 * the AEAD operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 *
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
int InitAead(DxSramAddr_t ctxAddr);

/* !
 * This function is used to process a block(s) of data on AES machine.
 * The user must process any associated data followed by the text data
 * blocks. This function MUST be called after the InitCipher function.
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
int ProcessAead(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

/* !
 * This function is used as finish operation of AEAD. The function MUST either
 * be called after "InitCipher" or "ProcessCipher".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
int FinalizeAead(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

#endif /* SEP_AEAD_H */
