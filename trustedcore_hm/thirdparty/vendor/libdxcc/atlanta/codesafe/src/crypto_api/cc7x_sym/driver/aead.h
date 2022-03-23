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

#ifndef  _AEAD_H
#define  _AEAD_H

#include "mlli.h"
#include "dma_buffer.h"

/******************************************************************************
*				DEFINITIONS
******************************************************************************/

/******************************************************************************
*				MACROS
******************************************************************************/

/*!
  Set the internal machine work mode according to the given
  crypto direction
*/
#define SEP_AEAD_CCM_SET_INTERNAL_MODE(direction) \
	((direction) == DRV_CRYPTO_DIRECTION_ENCRYPT ? \
	SEP_AEAD_MODE_CCM_PE : SEP_AEAD_MODE_CCM_PD)

/******************************************************************************
*				ENUMS
******************************************************************************/
typedef enum SepAeadCcmMode {
	SEP_AEAD_MODE_NULL_MODE = -1,
	SEP_AEAD_MODE_CCM_A = 8,
	SEP_AEAD_MODE_CCM_PE = 9,
	SEP_AEAD_MODE_CCM_PD = 10,
	SEP_AEAD_MODE_RESERVE32B = INT32_MAX,
} SepAeadCcmMode_e;

/******************************************************************************
*				TYPE DEFINITIONS
******************************************************************************/


/******************************************************************************
*				FUNCTION PROTOTYPES
******************************************************************************/
/*!
 * This function is used to initialize the AES machine to perform
 * the AEAD operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in Host memory.
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int InitAead(CCSramAddr_t ctxAddr, uint32_t *pCtx);

/*!
 * This function is used to process a block(s) of data on AES machine.
 * The user must process any associated data followed by the text data
 * blocks. This function MUST be called after the InitCipher function.
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in Host memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int ProcessAead(CCSramAddr_t ctxAddr, uint32_t *pCtx, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

/*!
 * This function is used as finish operation of AEAD. The function MUST either
 * be called after "InitCipher" or "ProcessCipher".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in Host memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int FinalizeAead(CCSramAddr_t ctxAddr, uint32_t *pCtx, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

#endif /*_AEAD_H*/

