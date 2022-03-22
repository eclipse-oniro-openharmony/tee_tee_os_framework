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

#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_CRYS_SYM_DRIVER

#include "dx_pal_mem.h"
#include "cc_plat.h"
#include "mlli.h"
#include "hw_queue.h"
#include "sep_ctx.h"
#include "completion.h"
#include "dx_error.h"
#include "combined.h"
#include "cipher.h"
#include "hash.h"
#include "crys_combined.h"
#include "cc_plat.h"

/* !
 * Sets the AES core engine in the given context.
 *
 * \param pAesCtx The AES context
 * \param combinedMode The user combined scheme represented by 32 bits
 * \param engIdx The engine index in the combinedMode
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
static int SetAesCoreEngine(struct sep_ctx_cipher *pAesCtx, CombinedMode_t combinedMode, int engIdx)
{
    enum sep_engine_type engType;
    CrysCombinedEngineSource_e engSrc;
    SepCipherPrivateContext_s *pAesPrivateCtx = (SepCipherPrivateContext_s *)pAesCtx->reserved;

    SepCombinedEnginePropsGet(combinedMode, engIdx, &engSrc, &engType);

    if (engSrc == INPUT_NULL) {
        DX_PAL_LOG_ERR("Illigal AES engine source");
        return DX_RET_NOEXEC;
    } else if (engSrc == INPUT_DIN) {
        WriteContextWord(&pAesPrivateCtx->engineCore, SEP_AES_ENGINE1);
    } else {
        WriteContextWord(&pAesPrivateCtx->engineCore, SEP_AES_ENGINE2);
    }

    return DX_RET_OK;
}

/* !
 * Translates the Combined SeP mode to Combined HW mode.
 *
 * \param pCtx The Combined context
 * \param HwCombinedMode_t [out] The HW mode as specified in combined.h
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
static int GetCombinedHwMode(struct sep_ctx_combined *pCtx, HwCombinedMode_t *mode)
{
    switch (ReadContextWord(&pCtx->mode)) {
    case SEP_COMBINED_DIN_TO_AES_TO_HASH_MODE:
        *mode = HW_COMBINED_DIN_TO_AES_TO_HASH_MODE;
        break;
    case SEP_COMBINED_DIN_TO_AES_TO_HASH_AND_DOUT_MODE:
        *mode = HW_COMBINED_DIN_TO_AES_TO_HASH_AND_DOUT_MODE;
        break;
    case SEP_COMBINED_DIN_TO_AES_AND_HASH_MODE:
        *mode = HW_COMBINED_DIN_TO_AES_AND_HASH_MODE;
        break;
    case SEP_COMBINED_DIN_TO_AES_TO_AES_TO_DOUT_MODE:
        *mode = HW_COMBINED_DIN_TO_AES_TO_AES_TO_DOUT_MODE;
        break;
    default:
        DX_PAL_LOG_ERR("Unsupported Combined Mode\n");
        *mode = HW_COMBINED_NONE;
        return DX_RET_UNSUPP_ALG_MODE;
    }

    return DX_RET_OK;
}

/* !
 * Loads the state for each given sub-context associated within combined context.
 * This function iterates thru the sub-contexts specified in the configuration
 * scheme and invokes the propriatery LOAD state correspondingly.
 *
 * \param qid
 * \param pCtx Combined context which contains the associated sub-contexts
 * \param hashPadding Is HASH padding enabled/disabled
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
static int LoadCombinedState(int qid, struct sep_ctx_combined *pCtx, enum HashConfig1Padding hashPadding)
{
    HwCombinedMode_t combinedHwMode;
    int engIdx;
    int drvRc;
    struct sep_ctx_generic *sub_ctx;

    drvRc = GetCombinedHwMode(pCtx, &combinedHwMode);
    if (drvRc != DX_RET_OK) {
        return drvRc;
    }
    /* load state for each given context */
    for (engIdx = 0; ((engIdx < SEP_MAX_COMBINED_ENGINES) && ((void *)ReadContextWord(&pCtx->sub_ctx[engIdx]) != NULL));
         engIdx++) {
        sub_ctx = (struct sep_ctx_generic *)ReadContextWord(&pCtx->sub_ctx[engIdx]);
        switch (ReadContextWord(&sub_ctx->alg)) {
        case SEP_CRYPTO_ALG_AES: {
            struct sep_ctx_cipher *pAesCtx = (struct sep_ctx_cipher *)ReadContextWord(&pCtx->sub_ctx[engIdx]);
            SepCipherPrivateContext_s *pAesPrivateCtx = (SepCipherPrivateContext_s *)pAesCtx->reserved;

            /* set tunneling mode */
            switch (combinedHwMode) {
            case HW_COMBINED_DIN_TO_AES_TO_AES_AND_HASH_MODE:
            case HW_COMBINED_DIN_TO_AES_TO_AES_TO_DOUT_MODE:
            case HW_COMBINED_DIN_TO_AES_TO_AES_TO_HASH_MODE:
                WriteContextWord(&pAesPrivateCtx->isTunnelOp, (uint32_t)TUNNEL_ON);
                WriteContextWord(&pAesPrivateCtx->tunnetDir, (uint32_t)SEP_CRYPTO_DIRECTION_DECRYPT_ENCRYPT);
                break;
            default:
                WriteContextWord(&pAesPrivateCtx->isTunnelOp, (uint32_t)TUNNEL_OFF);
            }

            /* select AES core engine 1/2 */
            drvRc = SetAesCoreEngine(pAesCtx, (CombinedMode_t)ReadContextWord(&pCtx->mode), engIdx);
            if (drvRc != DX_RET_OK) {
                return drvRc;
            }

            if (ReadContextWord(&pAesCtx->mode) == SEP_CIPHER_XTS) {
                /* in XTS the key must be loaded first */
                LoadCipherKey(qid, pAesCtx);
                LoadCipherState(qid, pAesCtx, 0);
            } else {
                LoadCipherState(qid, pAesCtx, 0);
                LoadCipherKey(qid, pAesCtx);
            }
            break;
        }
        case SEP_CRYPTO_ALG_HASH:
            drvRc = LoadHashState(qid, (struct sep_ctx_hash *)ReadContextWord(&pCtx->sub_ctx[engIdx]), hashPadding);
            if (drvRc != DX_RET_OK) {
                return drvRc;
            }
            break;
        default:
            DX_PAL_LOG_ERR("Invalid alg");
            return DX_RET_UNSUPP_ALG;
        }
    }

    return DX_RET_OK;
}

/* !
 * Finalizes the combined operation according to the given SeP mode.
 * This function distinguishes
 *
 * \param qid
 * \param combinedSepMode Combined SeP mode as passed by the caller
 * \param pCtx Combined context
 * \param isDataToFinalize Is there's any data reminder
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
static int FinalizeCombinedOp(int qid, enum SepCombinedMode combinedSepMode, struct sep_ctx_combined *pCtx,
                              int isDataToFinalize)
{
    HwDesc_s desc;
    int drvRc = DX_RET_OK;

    switch (combinedSepMode) {
    case SEP_COMBINED_DIN_TO_AES_AND_HASH_MODE:
    case SEP_COMBINED_DIN_TO_AES_TO_HASH_MODE:
    case SEP_COMBINED_DIN_TO_AES_TO_HASH_AND_DOUT_MODE: {
        struct sep_ctx_hash *pHashCtx = (struct sep_ctx_hash *)ReadContextWord(&pCtx->sub_ctx[1]);
        uint32_t hw_mode, DigestSize;
        DmaBuffer_s EmptyDmaBuffer;

        if (pHashCtx == NULL) {
            DX_PAL_LOG_ERR("NULL pointer for HASH context\n");
            drvRc = DX_RET_INVARG;
            goto EndWithErr;
        }

        if (isDataToFinalize) {
            drvRc = GetHashHwMode(ReadContextWord(&pHashCtx->mode), &hw_mode);
            if (drvRc != DX_RET_OK) {
                goto EndWithErr;
            }
            drvRc = GetHashHwDigestSize(ReadContextWord(&pHashCtx->mode), &DigestSize);
            if (drvRc != DX_RET_OK) {
                goto EndWithErr;
            }

            /* finalize operations with remaining data */
            HW_DESC_INIT(&desc);
            HW_DESC_SET_CIPHER_MODE(&desc, hw_mode);
            HW_DESC_SET_STATE_DOUT_PARAM(&desc, (uint32_t)pHashCtx->digest, DigestSize);
            if (hw_mode == SEP_HASH_HW_MD5 || hw_mode == SEP_HASH_HW_SHA512 || hw_mode == SEP_HASH_HW_SHA384) {
                HW_DESC_SET_BYTES_SWAP(&desc, 1);
            } else {
                HW_DESC_SET_CIPHER_CONFIG0(&desc, HASH_DIGEST_RESULT_LITTLE_ENDIAN);
            }
            HW_DESC_SET_CIPHER_CONFIG1(&desc, HASH_PADDING_DISABLED);
            HW_DESC_SET_CIPHER_DO(&desc, DO_NOT_PAD);
            HW_DESC_SET_FLOW_MODE(&desc, S_HASH_to_DOUT);
            HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
            AddHWDescSequence(qid, &desc);
        } else {
            /* finalize operations without remaining data */
            EmptyDmaBuffer.dmaBufType = DMA_BUF_SEP;
            EmptyDmaBuffer.axiNs      = AXI_SECURE;
            EmptyDmaBuffer.pData      = 0;
            EmptyDmaBuffer.size       = 0;

            drvRc = FinalizeHash(pHashCtx, &EmptyDmaBuffer, NULL);
            if (drvRc != DX_RET_OK) {
                goto EndWithErr;
            }
        }

        break;
    }
    case SEP_COMBINED_DIN_TO_AES_TO_AES_TO_DOUT_MODE:
        break;
    default:
        DX_PAL_LOG_ERR("Unsupported Combined Mode\n");
        drvRc = DX_RET_UNSUPP_ALG_MODE;
        break;
    }

EndWithErr:
    return drvRc;
}

/* ***************************************************************************** */
/* ***************************************************************************** */
/* !! we do not implement "InitCombined" since it does not perform any operation */
/* ***************************************************************************** */
/* ***************************************************************************** */

/* !
 * This function is used to process a block(s) of data in combined or tunneling mode.
 *
 * \param pCtx A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int ProcessCombined(struct sep_ctx_combined *pCtx, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
    DxDmaAddr_t pInputData = 0, pOutputData = 0;
    uint32_t DataInSize = 0, DataOutSize = 0;
    DmaMode_t dmaInMode = NO_DMA, dmaOutMode = NO_DMA;
    uint8_t inAxiNs                 = pDmaInputBuffer->axiNs;
    uint8_t outAxiNs                = pDmaOutputBuffer->axiNs;
    HwCombinedMode_t combinedHwMode = HW_COMBINED_NONE;
    HwDesc_s desc;
    struct sep_ctx_generic *sub_ctx;
    int isInplaceOp;

    int qid = CURR_QUEUE_ID();
    int engIdx;
    int drvRc = DX_RET_OK;

    drvRc = GetCombinedHwMode(pCtx, &combinedHwMode);
    if (drvRc != DX_RET_OK) {
        return drvRc;
    }
    isInplaceOp = (((pDmaInputBuffer->pData == pDmaOutputBuffer->pData) &&
                    (pDmaInputBuffer->dmaBufType == pDmaOutputBuffer->dmaBufType)) ||
                   (combinedHwMode == HW_COMBINED_DIN_TO_AES_TO_HASH_MODE) ||
                   (combinedHwMode == HW_COMBINED_DIN_TO_AES_TO_AES_TO_HASH_MODE));

    DX_PAL_LOG_INFO("Combined SEP mode = 0x%08x\n", (unsigned int)ReadContextWord(&pCtx->mode));
    DX_PAL_LOG_INFO("Combined HW mode = 0x%08x\n", combinedHwMode);

    /* load state for each given sub-context */
    drvRc = LoadCombinedState(qid, pCtx, HASH_PADDING_DISABLED);
    if (drvRc != DX_RET_OK) {
        goto EndWithErr;
    }

    dmaInMode  = DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType);
    dmaOutMode = DMA_BUF_TYPE_TO_MODE(pDmaOutputBuffer->dmaBufType);

    if ((!isInplaceOp) &&
        (((dmaInMode == NO_DMA) && (dmaOutMode != NO_DMA)) || ((dmaOutMode == NO_DMA) && (dmaInMode != NO_DMA)))) {
        DX_PAL_LOG_ERR("Inconsistent DMA mode for in/out buffers");
        drvRc = DX_RET_INVARG;
        goto EndWithErr;
    }

    switch (dmaInMode) {
    case DMA_MLLI:
        pInputData = GetFirstLliPtr(qid, MLLI_INPUT_TABLE);
        PrepareMLLITable(qid, pDmaInputBuffer->pData, pDmaInputBuffer->size, pDmaInputBuffer->axiNs, MLLI_INPUT_TABLE);
        /* data size should hold the number of LLIs */
        DataInSize = (pDmaInputBuffer->size) / LLI_ENTRY_BYTE_SIZE - 1; // reduce dummy entry (tail)
        break;
    case DMA_DLLI:
    case DMA_SRAM:
        pInputData = pDmaInputBuffer->pData;
        /* set the data size */
        DataInSize = pDmaInputBuffer->size;
        break;
    case NO_DMA:
        pInputData = 0;
        /* data size is meaningless in DMA-MLLI mode */
        DataInSize = 0;
        break;
    default:
        DX_PAL_LOG_ERR("Invalid DMA mode\n");
        drvRc = DX_RET_INVARG;
        goto EndWithErr;
    }

    if (isInplaceOp) {
        pOutputData = pInputData;
        DataOutSize = DataInSize;
    } else {
        switch (dmaOutMode) {
        case DMA_MLLI:
            /* get OUT MLLI tables pointer in SRAM (if not inplace operation) */
            pOutputData = (uint8_t *)GetFirstLliPtr(qid, MLLI_OUTPUT_TABLE);
            PrepareMLLITable(qid, pDmaOutputBuffer->pData, pDmaOutputBuffer->size, pDmaOutputBuffer->axiNs,
                             MLLI_OUTPUT_TABLE);
            /* data size should hold the number of LLIs */
            DataOutSize = (pDmaOutputBuffer->size) / LLI_ENTRY_BYTE_SIZE - 1; // reduce dummy entry (tail)
            break;
        case DMA_DLLI:
        case DMA_SRAM:
            pOutputData = (uint8_t *)pDmaOutputBuffer->pData;
            /* set the data size */
            DataOutSize = pDmaOutputBuffer->size;
            break;
        case NO_DMA:
            pOutputData = 0;
            /* data size is meaningless in DMA-MLLI mode */
            DataOutSize = 0;
            break;
        default:
            DX_PAL_LOG_ERR("Invalid DMA mode\n");
            drvRc = DX_RET_INVARG;
            goto EndWithErr;
        }
    }

    /* process the flow */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_TYPE(&desc, dmaInMode, pInputData, DataInSize, QID_TO_AXI_ID(qid), inAxiNs);
    switch (combinedHwMode) {
    case HW_COMBINED_DIN_TO_AES_TO_HASH_MODE:
    case HW_COMBINED_DIN_TO_AES_TO_AES_TO_HASH_MODE:
        break;
    default:
        HW_DESC_SET_DOUT_TYPE(&desc, dmaOutMode, (uint32_t)pOutputData, DataOutSize, QID_TO_AXI_ID(qid), outAxiNs);
    }
    HW_DESC_SET_FLOW_MODE(&desc, combinedHwMode);
    AddHWDescSequence(qid, &desc);

    /* store machine state for each sub context */
    for (engIdx = 0;
         ((engIdx < SEP_MAX_COMBINED_ENGINES) && ((uint32_t *)ReadContextWord(&pCtx->sub_ctx[engIdx]) != NULL));
         engIdx++) {
        sub_ctx = (struct sep_ctx_generic *)ReadContextWord(&pCtx->sub_ctx[engIdx]);
        switch (ReadContextWord(&sub_ctx->alg)) {
        case SEP_CRYPTO_ALG_AES:
            StoreCipherState(qid, (struct sep_ctx_cipher *)sub_ctx);
            break;
        case SEP_CRYPTO_ALG_HASH:
            StoreHashState(qid, (struct sep_ctx_hash *)sub_ctx);
            break;
        default:
            DX_PAL_LOG_ERR("Invalid Alg mode\n");
            drvRc = DX_RET_UNSUPP_ALG;
            goto EndWithErr;
        }
    }

EndWithErr:
    return drvRc;
}

/* !
 * This function is used as finish operation of Combined modes.
 * The function should be called after "ProcessCombined".
 *
 * \param pCtx A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int FinalizeCombined(struct sep_ctx_combined *pCtx, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
    HwCombinedMode_t combinedHwMode = HW_COMBINED_NONE;
    uint8_t inAxiNs                 = pDmaInputBuffer->axiNs;
    uint8_t outAxiNs                = pDmaOutputBuffer->axiNs;
    DxDmaAddr_t pInputData = 0, pOutputData = 0;
    uint32_t DataInSize = 0, DataOutSize = 0;
    uint32_t isRemainingData = 0;
    DmaMode_t dmaInMode      = NO_DMA;
    DmaMode_t dmaOutMode     = NO_DMA;
    HwDesc_s desc;
    int isInplaceOp;
    int qid   = CURR_QUEUE_ID();
    int drvRc = DX_RET_OK;

    HW_DESC_INIT(&desc);

    drvRc = GetCombinedHwMode(pCtx, &combinedHwMode);
    if (drvRc != DX_RET_OK) {
        return drvRc;
    }

    dmaInMode   = DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType);
    dmaOutMode  = DMA_BUF_TYPE_TO_MODE(pDmaOutputBuffer->dmaBufType);
    isInplaceOp = (((pDmaInputBuffer->pData == pDmaOutputBuffer->pData) &&
                    (pDmaInputBuffer->dmaBufType == pDmaOutputBuffer->dmaBufType)) ||
                   (combinedHwMode == HW_COMBINED_DIN_TO_AES_TO_HASH_MODE) ||
                   (combinedHwMode == HW_COMBINED_DIN_TO_AES_TO_AES_TO_HASH_MODE));

    /* check if we have remaining data to process */
    switch (dmaInMode) {
    case DMA_MLLI:
        isRemainingData = (pDmaInputBuffer->size > 0) ? 1 : 0;
        if (isRemainingData) {
            pInputData = GetFirstLliPtr(qid, MLLI_INPUT_TABLE);
            PrepareMLLITable(qid, pDmaInputBuffer->pData, pDmaInputBuffer->size, pDmaInputBuffer->axiNs,
                             MLLI_INPUT_TABLE);
        }
        /* data size should hold the number of LLIs */
        DataInSize = (pDmaInputBuffer->size) / LLI_ENTRY_BYTE_SIZE - 1; // reduce dummy entry (tail)
        break;
    case DMA_DLLI:
    case DMA_SRAM:
        isRemainingData = (pDmaInputBuffer->size > 0) ? 1 : 0;
        DataInSize      = pDmaInputBuffer->size;
        if (isRemainingData) {
            pInputData = pDmaInputBuffer->pData;
        }
        break;
    case NO_DMA:
        break;
    default:
        DX_PAL_LOG_ERR("Invalid DMA mode\n");
        drvRc = DX_RET_INVARG;
        goto EndWithErr;
    }

    if (isInplaceOp) {
        pOutputData = pInputData;
        DataOutSize = DataInSize;
    } else if (isRemainingData) {
        if (((dmaInMode == NO_DMA) && (dmaOutMode != NO_DMA)) || ((dmaOutMode == NO_DMA) && (dmaInMode != NO_DMA))) {
            DX_PAL_LOG_ERR("Inconsistent DMA mode for in/out buffers");
            drvRc = DX_RET_INVARG;
            goto EndWithErr;
        }

        /* check if we have remaining data to process */
        switch (dmaOutMode) {
        case DMA_MLLI:

            pOutputData = (uint8_t *)GetFirstLliPtr(qid, MLLI_OUTPUT_TABLE);
            PrepareMLLITable(qid, pDmaOutputBuffer->pData, pDmaOutputBuffer->size, pDmaOutputBuffer->axiNs,
                             MLLI_OUTPUT_TABLE);
            /* data size should hold the number of LLIs */
            DataOutSize = (pDmaOutputBuffer->size) / LLI_ENTRY_BYTE_SIZE - 1; // reduce dummy entry (tail)
            break;
        case DMA_DLLI:
        case DMA_SRAM:
            DataOutSize = pDmaOutputBuffer->size;
            pOutputData = (uint8_t *)pDmaOutputBuffer->pData;
            break;
        case NO_DMA:
            break;
        default:
            DX_PAL_LOG_ERR("Invalid DMA mode\n");
            drvRc = DX_RET_INVARG;
            goto EndWithErr;
        }
    }

    /* check if there is a remainder */
    if (isRemainingData == 1) {
        /* load state for each given sub-context */
        drvRc = LoadCombinedState(qid, pCtx, HASH_PADDING_ENABLED);
        if (drvRc != DX_RET_OK) {
            goto EndWithErr;
        }

        /* clobber remaining HASH data */
        HW_DESC_SET_DIN_TYPE(&desc, dmaInMode, pInputData, DataInSize, QID_TO_AXI_ID(qid), inAxiNs);
        switch (combinedHwMode) {
        case HW_COMBINED_DIN_TO_AES_TO_HASH_MODE:
        case HW_COMBINED_DIN_TO_AES_TO_AES_TO_HASH_MODE:
            break;
        default:
            HW_DESC_SET_DOUT_TYPE(&desc, dmaOutMode, (uint32_t)pOutputData, DataOutSize, QID_TO_AXI_ID(qid), outAxiNs);
        }
        HW_DESC_SET_FLOW_MODE(&desc, combinedHwMode);
        AddHWDescSequence(qid, &desc);
    }

    return FinalizeCombinedOp(qid, ReadContextWord(&pCtx->mode), pCtx, isRemainingData);

EndWithErr:
    return drvRc;
}
