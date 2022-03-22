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

#ifndef  _CIPHER_H
#define  _CIPHER_H

#include "cc_plat.h"
#include "mlli.h"
#include "cc_crypto_ctx.h"
#include "dma_buffer.h"
#include "cc_hw_queue_defs.h"

/******************************************************************************
*				DEFINITIONS
******************************************************************************/
#define AES_XCBC_MAC_NUM_KEYS 3
#define AES_XCBC_MAC_KEY1 1
#define AES_XCBC_MAC_KEY2 2
#define AES_XCBC_MAC_KEY3 3

#define AES_BLOCK_MASK 0xF
/******************************************************************************
*				TYPE DEFINITIONS
******************************************************************************/


/*
  RFC 3566 chapter 4 keys definitions
  This structure must be located at struct drv_ctx_cipher field "key"
*/
typedef struct XcbcMacRfcKeys {
	uint8_t K[CC_AES_128_BIT_KEY_SIZE];
	uint8_t K1[CC_AES_128_BIT_KEY_SIZE];
	uint8_t K2[CC_AES_128_BIT_KEY_SIZE];
	uint8_t K3[CC_AES_128_BIT_KEY_SIZE];
} XcbcMacRfcKeys_s;



/******************************************************************************
*				TYPE DEFINITIONS
******************************************************************************/


/******************************************************************************
*				FUNCTION PROTOTYPES
******************************************************************************/
/*!
 * Load AES state from context
 *
 * \param ctxAddr
 */
void LoadCipherState(CCSramAddr_t ctxAddr, uint8_t is_zero_iv, struct drv_ctx_cipher *pCipherContext);

/*!
 * Store AES state to context
 *
 * \param ctxAddr
 */
void StoreCipherState(CCSramAddr_t ctxAddr, struct drv_ctx_cipher *pCipherContext);

/*!
 * Load AES key
 *
 * \param ctxAddr
 */
void LoadCipherKey(CCSramAddr_t ctxAddr, struct drv_ctx_cipher *pCipherContext);

/*!
 * This function is used to initialize the AES machine to perform the AES
 * operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int InitCipher(CCSramAddr_t ctxAddr, uint32_t *pCtx);

/*!
 * This function is used to process block(s) of data using the AES machine.
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in Host memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int ProcessCipher(CCSramAddr_t ctxAddr, uint32_t *pCtx, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

/*!
 * This function is used as finish operation of AES on XCBC, CMAC, CBC
 * and other modes besides XTS mode.
 * The function may either be called after "InitCipher" or "ProcessCipher".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in Host memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int FinalizeCipher(CCSramAddr_t ctxAddr, uint32_t *pCtx, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

/*!
 * This function is used as finish operation of AES CTS mode.
 * The function may either be called after "InitCipher" or "ProcessCipher".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pCtx A pointer to the AES context buffer in Host memory.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int ProcessCTSFinalizeCipher(CCSramAddr_t ctxAddr, uint32_t *pCtx, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

#endif /*SEP_CIPHER_H*/

