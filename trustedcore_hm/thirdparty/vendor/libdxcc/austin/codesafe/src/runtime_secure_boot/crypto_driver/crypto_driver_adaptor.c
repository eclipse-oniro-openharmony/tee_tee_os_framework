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

#include "crypto_driver_defs.h"
#include "crypto_driver.h"
#include "dx_pal_dma.h"
#include "dx_pal_abort.h"
#include "secureboot_error.h"
#include "dx_pal_mem.h"

/* !
 * @brief This function is wrapper function for SBROM_CryptoInitDriver.
 * The function performs mapping/unmapping for DMA data and
 * calls to SBROM_CryptoInitDriver function.
 *
 * @param[in] aesKeyPtr             - virtual pointer to AES key
 * @param[in] aesIvPtr        -  virtual pointer to AES IV
 * @param[in] cryptoDriverMode  - can be one of CryptoDriverMode_t
 *
 * @return none
 */
DxError_t SB_CryptoInit(AES_Key_t *aesKeyPtr, AES_Iv_t *aesIvPtr, CryptoDriverMode_t cryptoDriverMode)
{
    DxError_t error              = DX_SUCCESS;
    uint8_t *tempAesKeyPtr       = NULL;
    DxDmaAddr_t mappedAesKeyAddr = 0;
    uint8_t *tempAesIVPtr        = NULL;
    DxDmaAddr_t mappedAesIvAddr  = 0;

    /* Perform allocation of DMA buffer for AES key */
    error = DX_PAL_DmaContigBufferAllocate(sizeof(AES_Key_t), (uint8_t **)&tempAesKeyPtr);

    if (error != DX_SUCCESS && tempAesKeyPtr != NULL) {
        error = DX_SB_DRV_MEMORY_ERROR_ERR;
        return error;
    }

    /* Get physical address of the mapped AES buffer */
    mappedAesKeyAddr = DX_PAL_MapVirtualToPhysical(tempAesKeyPtr);

    /* Copy AES key to the mapped address */
    DX_PAL_MemCopy(tempAesKeyPtr, (uint8_t *)aesKeyPtr, sizeof(AES_Key_t));

    /* Perform allocation of DMA buffer for AES IV */
    error = DX_PAL_DmaContigBufferAllocate(sizeof(AES_Iv_t), (uint8_t **)&tempAesIVPtr);

    if (error != DX_SUCCESS && tempAesIVPtr != NULL) {
        error = DX_SB_DRV_MEMORY_ERROR_ERR;
        goto End;
    }

    /* Get physical address of the mapped AES IV buffer */
    mappedAesIvAddr = DX_PAL_MapVirtualToPhysical(tempAesIVPtr);

    /* Copy AES IV to the mapped address */
    DX_PAL_MemCopy(tempAesIVPtr, (uint8_t *)aesIvPtr, sizeof(AES_Iv_t));

    error = SB_CryptoInitDriver(mappedAesKeyAddr, mappedAesIvAddr, cryptoDriverMode);

End:
    /* Free allocated DMA buffer */
    if (tempAesIVPtr != NULL)
        DX_PAL_DmaContigBufferFree(sizeof(AES_Iv_t), tempAesIVPtr);

    /* Free allocated DMA buffer */
    if (tempAesKeyPtr != NULL)
        DX_PAL_DmaContigBufferFree(sizeof(AES_Key_t), tempAesKeyPtr);

    return error;
}

/* !
 * @brief This function is wrapper function for SBROM_CryptoUpdateBlockDriver.
 * The function performs mapping/unmapping for DMA data and
 * calls to SBROM_CryptoUpdateBlockDriver function.
 *
 * @param[in] inputDataAddr     - address of the users data input buffer.
 * @param[out] outputDataAddr     - address of the users data output buffer.
 * @param[in] BlockSize        - number of bytes to update.
 *                                if it is not the last block, the size must be a multiple of AES blocks.
 * @param[in] isLastBlock      - if false, just updates the data; otherwise, enable hash padding
 * @param[in] cryptoDriverMode  - can be one of CryptoDriverMode_t
 * @param[in] isWaitForCryptoCompletion -enum for crypto operation completion mode
 *
 */
DxError_t SB_CryptoUpdateBlock(DxDmaAddr_t inputDataAddr, DxDmaAddr_t outputDataAddr, uint32_t BlockSize,
                               uint8_t isLastBlock, CryptoDriverMode_t cryptoDriverMode,
                               DX_SB_CryptoCompletionMode_t isWaitForCryptoCompletion)
{
    DxError_t error = DX_SUCCESS;

    error = SB_CryptoUpdateBlockDriver(inputDataAddr, outputDataAddr, BlockSize, isLastBlock, cryptoDriverMode,
                                       isWaitForCryptoCompletion);

    return error;
}

/* !
 * @brief This function is wrapper function for SBROM_CryptoFinishDriver.
 * The function performs mapping/unmapping for DMA data and
 * calls to SBROM_CryptoFinishDriver function.
 *
 * @param[out] hashResult     - the HASH result.
 *
 */
DxError_t SB_CryptoFinish(HASH_Result_t hashResult)
{
    DxError_t error              = DX_SUCCESS;
    DxDmaAddr_t mappedHashResult = 0;
    uint8_t *tempHashResultPtr   = NULL;

    /* Perform allocation of DMA buffer for HASH result */
    error = DX_PAL_DmaContigBufferAllocate(sizeof(HASH_Result_t), (uint8_t **)&tempHashResultPtr);

    if (error != DX_SUCCESS && tempHashResultPtr != NULL) {
        error = DX_SB_DRV_MEMORY_ERROR_ERR;
        return error;
    }

    /* Get physical address of the mapped HASH result buffer */
    mappedHashResult = DX_PAL_MapVirtualToPhysical(tempHashResultPtr);

    SB_CryptoFinishDriver(mappedHashResult);

    /* Copy HASH result to hashResult buffer */
    DX_PAL_MemCopy((uint8_t *)hashResult, (uint8_t *)tempHashResultPtr, HASH_DIGEST_SIZE_IN_BYTES);

    /* Free allocated DMA buffer */
    if (tempHashResultPtr != NULL)
        DX_PAL_DmaContigBufferFree(sizeof(HASH_Result_t), tempHashResultPtr);

    return error;
}
