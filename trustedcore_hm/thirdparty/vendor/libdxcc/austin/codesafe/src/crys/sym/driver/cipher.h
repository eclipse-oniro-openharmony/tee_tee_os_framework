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

#ifndef SEP_CIPHER_H
#define SEP_CIPHER_H

#include "cc_plat.h"
#include "mlli.h"
#include "sep_ctx.h"
#include "dma_buffer.h"
#include "hw_queue_defs.h"

/* *****************************************************************************
 *                DEFINITIONS
 * *************************************************************************** */
#define AES_XCBC_MAC_NUM_KEYS 3
#define AES_XCBC_MAC_KEY1     1
#define AES_XCBC_MAC_KEY2     2
#define AES_XCBC_MAC_KEY3     3

#define AES_BLOCK_MASK 0xF
/* *****************************************************************************
 *                TYPE DEFINITIONS
 * *************************************************************************** */
typedef enum DataBlockType { FIRST_BLOCK, MIDDLE_BLOCK, LAST_BLOCK, RESERVE32B_BLOCK = INT32_MAX } DataBlockType_t;

typedef enum SepAesCoreEngine {
    SEP_AES_ENGINE1,
    SEP_AES_ENGINE2,
    SEP_AES_ENGINES_RESERVE32B = INT32_MAX
} SepAesCoreEngine_t;

/*
  RFC 3566 chapter 4 keys definitions
  This structure must be located at struct sep_ctx_cipher field "key"
*/
typedef struct XcbcMacRfcKeys {
    uint8_t K[SEP_AES_128_BIT_KEY_SIZE];
    uint8_t K1[SEP_AES_128_BIT_KEY_SIZE];
    uint8_t K2[SEP_AES_128_BIT_KEY_SIZE];
    uint8_t K3[SEP_AES_128_BIT_KEY_SIZE];
} XcbcMacRfcKeys_s;

typedef struct SepAesPrivateContext {
    /* this flag indicates whether the user processed at least
       one data block:
       "0" no data blocks processed
       "1" at least one data block processed */
    DataBlockType_t dataBlockType;
    TunnelOp_t isTunnelOp;
    SepAesCoreEngine_t engineCore;
    uint32_t tunnetDir;
} SepCipherPrivateContext_s;

/* *****************************************************************************
 *                TYPE DEFINITIONS
 * *************************************************************************** */

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */
/* !
 * Load AES state from context
 *
 * \param qid
 * \param ctxAddr
 */
void LoadCipherState(int qid, DxSramAddr_t ctxAddr, uint8_t is_zero_iv);

/* !
 * Store AES state to context
 *
 * \param qid
 * \param ctxAddr
 */
void StoreCipherState(int qid, DxSramAddr_t ctxAddr);

/* !
 * Load AES key
 *
 * \param qid
 * \param ctxAddr
 */
void LoadCipherKey(int qid, DxSramAddr_t ctxAddr);

/* !
 * This function is used to initialize the AES machine to perform the AES
 * operations. This should be the first function called.
 *
 * \param ctxAddr A pointer to the context buffer in SRAM.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int InitCipher(DxSramAddr_t ctxAddr);

/* !
 * This function is used to process block(s) of data using the AES machine.
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int ProcessCipher(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

/* !
 * This function is used as finish operation of AES on XCBC, CMAC, CBC
 * and other modes besides XTS mode.
 * The function may either be called after "InitCipher" or "ProcessCipher".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int FinalizeCipher(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

/* !
 * This function is used as finish operation of AES CTS mode.
 * The function may either be called after "InitCipher" or "ProcessCipher".
 *
 * \param ctxAddr A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int ProcessCTSFinalizeCipher(DxSramAddr_t ctxAddr, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

#endif /* SEP_CIPHER_H */
