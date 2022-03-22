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

#ifndef _CRYPTO_DRIVER_H
#define _CRYPTO_DRIVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "hw_queue_defs.h"
#include "crypto_driver_defs.h"
#include "cc_plat.h"

#ifdef BIG__ENDIAN
#define HASH_SHA256_VAL 0x19CDE05B, 0xABD9831F, 0x8C68059B, 0x7F520E51, 0x3AF54FA5, 0x72F36E3C, 0x85AE67BB, 0x67E6096A
#else
#define HASH_SHA256_VAL 0x5BE0CD19, 0x1F83D9AB, 0x9B05688C, 0x510E527F, 0xA54FF53A, 0x3C6EF372, 0xBB67AE85, 0x6A09E667
#endif

/* ----------------------------
      PUBLIC FUNCTIONS
----------------------------------- */

/* !
 * This function initializes the AES and HASH HW engines according to required crypto operations.
 * This should be the first function called.
 *
 * @param[in] hwBaseAddress     - cryptocell base address
 * @param[in] aesKey_ptr    - the address of the AES key
 * @param[in] aesIv_ptr        - the address of the AES IV
 * @param[in] cryptoDriverMode  - can be one of CryptoDriverMode_t
 *
 */
DxError_t SB_CryptoInitDriver(DxDmaAddr_t aesKeyAddr, DxDmaAddr_t aesIvAddr, CryptoDriverMode_t cryptoDriverMode);

/* !
 * This function is used to do cryptographic operations on a block(s) of data using HASH and/or AES machines.
 *
 * @param[in] hwBaseAddress     - cryptocell base address
 * @param[in] inputDataAddr     - address of the users data input buffer.
 * @param[out] outputDataAddr     - address of the users data output buffer.
 * @param[in] BlockSize         - number of bytes to update.
 *                                if it is not the last block, the size must be a multiple of AES blocks.
 * @param[in] isLastBlock      - if false, just updates the data; otherwise, enable hash padding
 * @param[in] cryptoDriverMode  - can be one of CryptoDriverMode_t
 * @param[in] isWaitForCryptoCompletion -enum for crypto operation completion mode
 *
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from secureboot_error.h
 */
DxError_t SB_CryptoUpdateBlockDriver(DxDmaAddr_t inputDataAddr, DxDmaAddr_t outputDataAddr, uint32_t BlockSize,
                                     uint8_t isLastBlock, CryptoDriverMode_t cryptoDriverMode,
                                     DX_SB_CryptoCompletionMode_t isWaitForCryptoCompletion);

/* !
 * This function returns the digest result of crypto hash operation.
 *
 * @param[in] hwBaseAddress     - cryptocell base address
 * @param[out] hashResult     - the address of HASH result.
 *
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from secureboot_error.h
 */
void SB_CryptoFinishDriver(DxDmaAddr_t hashResult);

/* !
 * @brief This function adds a HW descriptor sequence to HW queue 0.
 *
 * @param[in] hwBaseAddress     - cryptocell base address
 * @param[in] descSeq        - a pointer to a HW descriptor sequence (5 words)
 *
 * @return none
 */

/* !
 * @brief This function is wrapper function for SBROM_CryptoInitDriver.
 * The function performs mapping/unmapping for DMA data and
 * calls to SBROM_CryptoInitDriver function.
 *
 * @param[in] hwBaseAddress     - cryptocell base address
 * @param[in] aesKey_ptr    - a pointer to AES key
 * @param[in] aesIv_ptr        - a pointer to AES IV
 * @param[in] cryptoDriverMode  - can be one of CryptoDriverMode_t
 *
 * @return none
 */

DxError_t SB_CryptoInit(AES_Key_t *aesKeyPtr, AES_Iv_t *aesIvPtr, CryptoDriverMode_t cryptoDriverMode);
/* !
 * @brief This function is wrapper function for SBROM_CryptoUpdateBlockDriver.
 * The function performs mapping/unmapping for DMA data and
 * calls to SBROM_CryptoUpdateBlockDriver function.
 *
 * @param[in] hwBaseAddress     - cryptocell base address
 * @param[in] inputData_ptr     - a pointer to the users data input buffer.
 * @param[out] outputData_ptr     - a pointer to the users data output buffer.
 * @param[in] BlockSize        - number of bytes to update.
 *                                if it is not the last block, the size must be a multiple of AES blocks.
 * @param[in] isLastBlock      - if false, just updates the data; otherwise, enable hash padding
 * @param[in] cryptoDriverMode  - can be one of CryptoDriverMode_t
 * @param[in] isWaitForCryptoCompletion -enum for crypto operation completion mode
 *
 */
DxError_t SB_CryptoUpdateBlock(DxDmaAddr_t inputDataAddr, DxDmaAddr_t outputDataAddr, uint32_t BlockSize,
                               uint8_t isLastBlock, CryptoDriverMode_t cryptoDriverMode,
                               DX_SB_CryptoCompletionMode_t isWaitForCryptoCompletion);

/* !
 * @brief This function is wrapper function for SBROM_CryptoFinishDriver.
 * The function performs mapping/unmapping for DMA data and
 * calls to SBROM_CryptoFinishDriver function.
 *
 * @param[in] hwBaseAddress     - cryptocell base address
 * @param[out] hashResult     - the HASH result.
 *
 */
DxError_t SB_CryptoFinish(HASH_Result_t hashResult);

#ifdef __cplusplus
}
#endif

#endif
