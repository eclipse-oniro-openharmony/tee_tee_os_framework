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

/* ************ Include Files ************** */

#include "dx_pal_types.h"
#include "secureboot_error.h"
#include "util.h"
#include "crypto_driver_defs.h"
#include "crypto_driver.h"
#include "sep_ctx.h"
#include "dx_hal_plat.h"
#include "completion.h"
#include "hw_queue.h"
#include "dx_pal_mem.h"
#include "dx_pal_dma.h"

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* !
 * This function initializes the AES and HASH HW engines according to required crypto operations.
 * This should be the first function called.
 *
 * @param[in] hwBaseAddress     - cryptocell base address
 * @param[in] aesKeyAddr    - the address of the AES key
 * @param[in] aesIvAddr        - the address of the AES IV
 * @param[in] cryptoDriverMode  - can be one of CryptoDriverMode_t
 *
 */
DxError_t SB_CryptoInitDriver(DxDmaAddr_t aesKeyAddr, DxDmaAddr_t aesIvAddr, CryptoDriverMode_t cryptoDriverMode)
{
    HwDesc_s desc;
    uint32_t keySizeInBytes = SEP_AES_128_BIT_KEY_SIZE;
    int qid                 = CURR_QUEUE_ID();
    uint8_t *tmpVirtAddr_ptr;

    const uint32_t hashInitialDigest[] = { HASH_SHA256_VAL };
    DxDmaAddr_t mappedAddr             = 0;

    /* error variable */
    DxError_t error = DX_SUCCESS;

    /* Allocate DMA contiguous buffer for HASH digest */
    error = DX_PAL_DmaContigBufferAllocate(HASH_DIGEST_SIZE_IN_BYTES, &tmpVirtAddr_ptr);

    if (error != DX_SUCCESS) {
        error = DX_SB_DRV_MEMORY_ERROR_ERR;
        return error;
    }
    /* Get physical address of the mapped buffer */
    mappedAddr = DX_PAL_MapVirtualToPhysical(tmpVirtAddr_ptr);

    /* Copy HASH digest value to the mapped buffer */
    DX_PAL_MemCopy(tmpVirtAddr_ptr, (uint8_t *)hashInitialDigest, HASH_DIGEST_SIZE_IN_BYTES);

    if ((cryptoDriverMode == CRYPTO_DRIVER_HASH_MODE) || (cryptoDriverMode == CRYPTO_DRIVER_HASH_AES_CTR_MODE)) {
        /* Load hash digest */
        HW_DESC_INIT(&desc);
        HW_DESC_SET_CIPHER_MODE(&desc, SEP_HASH_HW_SHA256);
        HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE0);
        HW_DESC_SET_DIN_TYPE(&desc, DMA_DLLI, mappedAddr, HASH_DIGEST_SIZE_IN_BYTES, QID_TO_AXI_ID(qid), AXI_SECURE);

        AddHWDescSequence(qid, &desc);

        /* Load hash current length */
        HW_DESC_INIT(&desc);
        HW_DESC_SET_CIPHER_MODE(&desc, SEP_HASH_HW_SHA256);
        HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_HASH);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
        HW_DESC_SET_DIN_CONST(&desc, 0, HASH_LENGTH_SIZE_IN_BYTES);
        AddHWDescSequence(qid, &desc);
    }

    if ((cryptoDriverMode == CRYPTO_DRIVER_AES_CTR_MODE) || (cryptoDriverMode == CRYPTO_DRIVER_HASH_AES_CTR_MODE)) {
        /* Load CTR IV */
        HW_DESC_INIT(&desc);
        HW_DESC_SET_CIPHER_MODE(&desc, SEP_CIPHER_CTR);
        HW_DESC_SET_CIPHER_CONFIG0(&desc, DESC_DIRECTION_ENCRYPT_ENCRYPT);
        HW_DESC_SET_KEY_SIZE_AES(&desc, keySizeInBytes);
        HW_DESC_SET_DIN_TYPE(&desc, DMA_DLLI, aesIvAddr, AES_IV_COUNTER_SIZE_IN_BYTES, QID_TO_AXI_ID(qid), AXI_SECURE);

        HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE1);
        AddHWDescSequence(qid, &desc);

        /* Load CTR key */
        HW_DESC_INIT(&desc);
        HW_DESC_SET_CIPHER_MODE(&desc, SEP_CIPHER_CTR);
        HW_DESC_SET_CIPHER_CONFIG0(&desc, DESC_DIRECTION_ENCRYPT_ENCRYPT);
        HW_DESC_SET_KEY_SIZE_AES(&desc, keySizeInBytes);
        HW_DESC_SET_DIN_TYPE(&desc, DMA_DLLI, aesKeyAddr, AES_KEY_SIZE_IN_BYTES, QID_TO_AXI_ID(qid), AXI_SECURE);
        HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_AES);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
        AddHWDescSequence(qid, &desc);
    }

    /* Free allocated DMA buffer */
    error = DX_PAL_DmaContigBufferFree(HASH_DIGEST_SIZE_IN_BYTES, tmpVirtAddr_ptr);
    if (error != DX_SUCCESS) {
        error = DX_SB_DRV_MEMORY_ERROR_ERR;
    }
    return error;
}

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
 * @return DxError_t - On success the value DX_SUCCESS is returned,
 *         on failure - a value from secureboot_error.h
 */
DxError_t SB_CryptoUpdateBlockDriver(DxDmaAddr_t inputDataAddr, DxDmaAddr_t outputDataAddr, uint32_t BlockSize,
                                     uint8_t isLastBlock, CryptoDriverMode_t cryptoDriverMode,
                                     DX_SB_CryptoCompletionMode_t isWaitForCryptoCompletion)
{
    HwDesc_s desc;
    uint8_t *tmpHashLengthptr = NULL;
    DxDmaAddr_t mappedAddr;
    int qid = CURR_QUEUE_ID();

    /* error variable */
    DxError_t error = DX_SUCCESS;

    /* Allocate DMA contiguous buffer for update hash result */
    error = DX_PAL_DmaContigBufferAllocate(sizeof(HASH_Result_t), (uint8_t **)(&tmpHashLengthptr));

    if (error != DX_SUCCESS) {
        error = DX_SB_DRV_MEMORY_ERROR_ERR;
        return error;
    }

    /* Get physical address of the  mapped buffer */
    mappedAddr = DX_PAL_MapVirtualToPhysical((uint8_t *)tmpHashLengthptr);

    if (isWaitForCryptoCompletion == DX_SB_CRYPTO_COMPLETION_WAIT_UPON_START) {
        /* wait for sequence to complete */
        WaitForSequenceCompletion();
    }

    /* Check last block to enable padding */
    if ((isLastBlock == DX_TRUE) &&
        ((cryptoDriverMode == CRYPTO_DRIVER_HASH_MODE) || (cryptoDriverMode == CRYPTO_DRIVER_HASH_AES_CTR_MODE))) {
        /* Get hash current length */
        HW_DESC_INIT(&desc);
        HW_DESC_SET_CIPHER_MODE(&desc, SEP_HASH_HW_SHA256);
        HW_DESC_SET_CIPHER_CONFIG1(&desc, DX_SB_HASH_PADDING_ENABLED);
        HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
        HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE1);
        HW_DESC_SET_DOUT_DLLI(&desc, mappedAddr, HASH_LENGTH_SIZE_IN_BYTES, QID_TO_AXI_ID(qid), AXI_SECURE, 0);
        AddHWDescSequence(qid, &desc);
    }

    /* Process input data */
    /* ******************* */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_TYPE(&desc, DMA_DLLI, inputDataAddr, BlockSize, QID_TO_AXI_ID(qid), AXI_SECURE);

    /* decide on crypto operation mode */
    switch (cryptoDriverMode) {
    case CRYPTO_DRIVER_HASH_MODE:
        HW_DESC_SET_FLOW_MODE(&desc, DIN_HASH);
        break;
    case CRYPTO_DRIVER_HASH_AES_CTR_MODE:
        HW_DESC_SET_FLOW_MODE(&desc, AES_and_HASH);
        HW_DESC_SET_DOUT_DLLI(&desc, outputDataAddr, BlockSize, QID_TO_AXI_ID(qid), AXI_SECURE, 0);
        break;
    case CRYPTO_DRIVER_AES_CTR_MODE:
        HW_DESC_SET_FLOW_MODE(&desc, DIN_AES_DOUT);
        HW_DESC_SET_DOUT_DLLI(&desc, outputDataAddr, BlockSize, QID_TO_AXI_ID(qid), AXI_SECURE, 0);
    default:
        break;
    }

    AddHWDescSequence(qid, &desc);

    /* trigger interrupt for sequential operations only (not for last) */
    switch (isWaitForCryptoCompletion) {
    case DX_SB_CRYPTO_COMPLETION_NO_WAIT_ASK_ACK:
    case DX_SB_CRYPTO_COMPLETION_WAIT_UPON_START:
        if (isLastBlock == DX_TRUE)
            break;
        /* else, fallthrough */
    case DX_SB_CRYPTO_COMPLETION_WAIT_UPON_END:
        /* wait for sequence to complete */
        WaitForSequenceCompletion();
    case DX_SB_CRYPTO_COMPLETION_NO_WAIT:
        break;
    default:
        error = DX_SB_DRV_ILLEGAL_INPUT_ERR;
    }

    /* Free allocated DMA buffer */
    if (tmpHashLengthptr != NULL)
        DX_PAL_DmaContigBufferFree(sizeof(HASH_Result_t), (uint8_t *)tmpHashLengthptr);

    return error;
}

/* !
 * This function returns the digest result of crypto hash operation.
 *
 * @param[in] hwBaseAddress     - cryptocell base address
 * @param[out] hashResult     - the HASH result.
 *
 * @void
 */
void SB_CryptoFinishDriver(DxDmaAddr_t hashResult)
{
    HwDesc_s desc;
    int qid = CURR_QUEUE_ID();

    /* Get the hash digest result */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_CIPHER_MODE(&desc, SEP_HASH_HW_SHA256);
    HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    HW_DESC_SET_CIPHER_CONFIG0(&desc, DX_SB_HASH_DIGEST_RESULT_LITTLE_ENDIAN);
    HW_DESC_SET_CIPHER_CONFIG1(&desc, DX_SB_HASH_PADDING_ENABLED);
    HW_DESC_SET_DOUT_DLLI(&desc, hashResult, HASH_DIGEST_SIZE_IN_BYTES, QID_TO_AXI_ID(qid), AXI_SECURE, 0);

    AddHWDescSequence(qid, &desc);

    /* wait for sequence to complete */
    WaitForSequenceCompletion();
}
