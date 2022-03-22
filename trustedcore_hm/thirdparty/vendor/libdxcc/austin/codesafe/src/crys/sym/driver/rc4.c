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

#include "dx_error.h"
#include "cc_plat.h"
#include "mlli.h"
#include "dma_buffer.h"
#include "hw_queue.h"
#include "sep_ctx.h"
#include "rc4.h"

/* !
 * This function is used to initialize the RC4 machine to perform the RC4
 * operations. This should be the first function called. It initializes
 * the permutation in the "S" array.
 *
 * \param pCtx A pointer to the context buffer in SRAM.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int InitRc4(struct sep_ctx_rc4 *pCtx)
{
    HwDesc_s desc;
    int qid = CURR_QUEUE_ID(); /* qid is stored in pxTaskTag field */

    /* check key size */
    if (ReadContextWord(&pCtx->key_size) < SEP_RC4_KEY_SIZE_MIN) {
        DX_PAL_LOG_ERR("RC4 key size MUST be >= 1\n");
        return DX_RET_INVARG;
    }
    if (ReadContextWord(&pCtx->key_size) > SEP_RC4_KEY_SIZE_MAX) {
        DX_PAL_LOG_ERR("RC4 key size MUST be <= 20\n");
        return DX_RET_INVARG;
    }

    /* load key -done only once per session */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_STATE_DIN_PARAM(&desc, (uint32_t)pCtx->key, ReadContextWord(&pCtx->key_size));
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_RC4);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_KEY0);
    AddHWDescSequence(qid, &desc);

    /* store state -this will ensure "S" array was created and stored in context */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, (uint32_t)pCtx->state, SEP_RC4_STATE_SIZE);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    HW_DESC_SET_FLOW_MODE(&desc, S_RC4_to_DOUT);
    AddHWDescSequence(qid, &desc);

    return DX_RET_OK;
}

/* !
 * This function is used to process a block(s) of data on RC4 machine.
 * This function may be called after the "InitRc4" function.
 *
 * \param pCtx A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int ProcessRc4(struct sep_ctx_rc4 *pCtx, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
    DxDmaAddr_t pInputData = 0, pOutputData = 0;
    uint32_t DataInSize = 0, DataOutSize = 0;
    const int isInplaceOp = ((pDmaInputBuffer->pData == pDmaOutputBuffer->pData) &&
                             (pDmaInputBuffer->dmaBufType == pDmaOutputBuffer->dmaBufType));
    HwDesc_s desc;
    DmaMode_t dmaInMode = NO_DMA, dmaOutMode = NO_DMA;
    uint8_t inAxiNs  = pDmaInputBuffer->axiNs;
    uint8_t outAxiNs = pDmaOutputBuffer->axiNs;
    int qid          = CURR_QUEUE_ID(); /* qid is stored in pxTaskTag field */
    int drvRc        = DX_RET_OK;

    /* load state */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_LOAD_STATE0);
    HW_DESC_SET_KEY_SIZE_AES(&desc, ReadContextWord(&pCtx->key_size));
    HW_DESC_SET_STATE_DIN_PARAM(&desc, (uint32_t)pCtx->state, SEP_RC4_STATE_SIZE);
    HW_DESC_SET_FLOW_MODE(&desc, S_DIN_to_RC4);
    AddHWDescSequence(qid, &desc);

    dmaInMode  = DMA_BUF_TYPE_TO_MODE(pDmaInputBuffer->dmaBufType);
    dmaOutMode = DMA_BUF_TYPE_TO_MODE(pDmaOutputBuffer->dmaBufType);

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
            pOutputData = GetFirstLliPtr(qid, MLLI_OUTPUT_TABLE);
            PrepareMLLITable(qid, pDmaOutputBuffer->pData, pDmaOutputBuffer->size, pDmaOutputBuffer->axiNs,
                             MLLI_OUTPUT_TABLE);
            /* data size should hold the number of LLIs */
            DataOutSize = (pDmaOutputBuffer->size) / LLI_ENTRY_BYTE_SIZE - 1; // reduce dummy entry (tail)

            break;
        case DMA_DLLI:
        case DMA_SRAM:
            pOutputData = pDmaOutputBuffer->pData;
            DataOutSize = pDmaOutputBuffer->size;
            break;
        default:
            DX_PAL_LOG_ERR("Invalid DMA mode\n");
            drvRc = DX_RET_INVARG;
            goto EndWithErr;
        }
    }

    /* process the RC4 flow */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_TYPE(&desc, dmaInMode, pInputData, DataInSize, QID_TO_AXI_ID(qid), inAxiNs);
    HW_DESC_SET_DOUT_TYPE(&desc, dmaOutMode, pOutputData, DataOutSize, QID_TO_AXI_ID(qid), outAxiNs);
    HW_DESC_SET_FLOW_MODE(&desc, DIN_RC4_DOUT);
    AddHWDescSequence(qid, &desc);

    /* store state */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_STATE_DOUT_PARAM(&desc, (uint32_t)pCtx->state, SEP_RC4_STATE_SIZE);
    HW_DESC_SET_SETUP_MODE(&desc, SETUP_WRITE_STATE0);
    HW_DESC_SET_FLOW_MODE(&desc, S_RC4_to_DOUT);
    AddHWDescSequence(qid, &desc);

EndWithErr:
    return drvRc;
}

/* !
 * This function is used as finish the RC4 operation.
 * The function may either be called after "InitRc4" or "ProcessRc4".
 *
 * \param pCtx A pointer to the AES context buffer in SRAM.
 * \param pDmaInputBuffer A structure which represents the DMA input buffer.
 * \param pDmaOutputBuffer A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int FinalizeRc4(struct sep_ctx_rc4 *pCtx, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer)
{
    uint32_t isRemainingData = 0;
    int drvRc                = DX_RET_OK;

    /* check if we have remaining data to process */
    switch (pDmaInputBuffer->dmaBufType) {
    case DMA_BUF_MLLI_IN_HOST:
        isRemainingData = (pDmaInputBuffer->size > 0) ? 1 : 0;
        break;
    case DMA_BUF_SEP:
    case DMA_BUF_DLLI:
        isRemainingData = (pDmaInputBuffer->size > 0) ? 1 : 0;
        break;
    default:
        DX_PAL_LOG_ERR("Invalid DMA mode\n");
        drvRc = DX_RET_INVARG;
        goto EndWithErr;
    }

    if (isRemainingData) {
        /* process all tables and get state from the RC4 machine */
        drvRc = ProcessRc4(pCtx, pDmaInputBuffer, pDmaOutputBuffer);
    }

EndWithErr:
    return drvRc;
}
