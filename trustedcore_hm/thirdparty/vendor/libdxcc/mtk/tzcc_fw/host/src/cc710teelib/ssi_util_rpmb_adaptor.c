/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include "sasi_context_relocation.h"
#include "ssi_sram_map.h"
#include "sasi_hmac.h"
#include "sasi_hmac_error.h"
#include "cc_plat.h"
#include "ssi_pal_mem.h"
#include "ssi_pal_perf.h"
#include "ssi_pal_log.h"
#include "ssi_pal_dma.h"
#include "ssi_pal_abort.h"
#include "ssi_pal_mutex.h"
#include "ssi_util_rpmb_adaptor.h"
#include "dma_buffer.h"
#include "sym_adaptor_driver_int.h"
#include "sym_crypto_driver.h"
#include "completion.h"

#ifdef DEBUG
#include <assert.h>
#endif

/* *********************** Statics **************************** */
static RpmbDmaBuildBuffer_t gDmaBuildBuffer;

int RpmbSymDriverAdaptorModuleInit()
{
    int symRc = SASI_RET_OK;

    /* allocate internal buffer for dma device resources */
    symRc = RpmbAllocDmaBuildBuffers(&gDmaBuildBuffer);

    if (symRc != SASI_RET_OK) {
        symRc = SASI_RET_NOMEM;
    }

    return symRc;
}

int RpmbSymDriverAdaptorModuleTerminate()
{
    /* release internal dma buffer resources */
    RpmbFreeDmaBuildBuffers(&gDmaBuildBuffer);

    return SASI_RET_OK;
}

SaSiError_t RpmbHmacUpdate(SaSi_HMACUserContext_t *ContextID_ptr, unsigned long *pListOfDataFrames, uint32_t listSize)
{
    struct drv_ctx_hmac *pHmacContext;
    SaSi_HMACPrivateContext_t *pHmacPrivContext;
    int symRc = SASI_RET_OK;

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct drv_ctx_hmac *)SaSi_GetUserCtxLocation(ContextID_ptr->buff);
    pHmacPrivContext =
        (SaSi_HMACPrivateContext_t *)&(((uint32_t *)pHmacContext)[SaSi_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    if (listSize == RPMB_MAX_BLOCKS_PER_UPDATE) {
        symRc = RpmbSymDriverAdaptorProcess((struct drv_ctx_generic *)pHmacContext, pListOfDataFrames, listSize);
        if (symRc != SASI_RET_OK) {
            return SASI_SaSi_RETURN_ERROR(symRc, 0, RpmbSymAdaptor2SasiHmacErr);
        }
    } else { /* this is the last block */
        pHmacPrivContext->isLastBlockProcessed = 1;
        symRc = RpmbSymDriverAdaptorFinalize((struct drv_ctx_generic *)pHmacContext, pListOfDataFrames, listSize);
        if (symRc != SASI_RET_OK) {
            return SASI_SaSi_RETURN_ERROR(symRc, 0, RpmbSymAdaptor2SasiHmacErr);
        }
    }

    if (symRc != SASI_RET_OK) {
        return SASI_SaSi_RETURN_ERROR(symRc, 0, RpmbSymAdaptor2SasiHmacErr);
    }

    return SaSi_OK;
}

SaSiError_t RpmbHmacFinish(SaSi_HMACUserContext_t *ContextID_ptr, SaSi_HASH_Result_t HmacResultBuff)
{
    struct drv_ctx_hmac *pHmacContext;
    SaSi_HMACPrivateContext_t *pHmacPrivContext;
    int symRc = SASI_RET_OK;

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct drv_ctx_hmac *)SaSi_GetUserCtxLocation(ContextID_ptr->buff);
    pHmacPrivContext =
        (SaSi_HMACPrivateContext_t *)&(((uint32_t *)pHmacContext)[SaSi_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    if (pHmacPrivContext->isLastBlockProcessed == 0) {
        symRc = RpmbSymDriverAdaptorFinalize((struct drv_ctx_generic *)pHmacContext, NULL, 0);
        if (symRc != SASI_RET_OK) {
            return SASI_SaSi_RETURN_ERROR(symRc, 0, RpmbSymAdaptor2SasiHmacErr);
        }
    }

    SaSi_PalMemCopy(HmacResultBuff, pHmacContext->digest, SEP_SHA256_DIGEST_SIZE);
    return SaSi_OK;
}

int RpmbSymDriverAdaptorProcess(struct drv_ctx_generic *pCtx, unsigned long *pListOfDataFrames, uint32_t listSize)
{
    int symRc = SASI_RET_OK;
    DmaBuffer_s dmaBuffIn;
    DmaBuffer_s dmaBuffOut;
    uint32_t retCode;
    SaSi_PalPerfData_t perfIdx = 0;

    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_PROC);
    SASI_PAL_LOG_INFO("pCtx=%p\n", pCtx);
    SASI_PAL_LOG_INFO("IN addr=%p OUT addr=%p DataSize=%u\n", pDataIn, pDataOut, DataSize);

    retCode = SaSi_PalMutexLock(&sasiSymCryptoMutex, SASI_INFINITE);
    if (retCode != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }

    retCode =
        RpmbBuildDmaFromDataPtr(pListOfDataFrames, listSize, SASI_PAL_DMA_DIR_TO_DEVICE, &dmaBuffIn, &gDmaBuildBuffer);
    if (retCode != 0) {
        SASI_PAL_LOG_ERR("failed to RpmbBuildDmaFromDataPtr for pDataIn 0x%x\n", retCode);
        symRc = retCode;
        goto processUnlockMutex;
    }

    symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_in, SASI_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx);
    if (symRc != SASI_RET_OK) {
        goto EndWithErr;
    }

    symRc = SymDriverDispatchProcess(SASI_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, &dmaBuffIn, &dmaBuffOut);
    if (symRc != SASI_RET_OK) {
        goto EndWithErr;
    }

    WaitForSequenceCompletion();
    symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_out, SASI_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx);

EndWithErr:

    retCode = RpmbBuildDataPtrFromDma(pListOfDataFrames, listSize, SASI_PAL_DMA_DIR_TO_DEVICE, &gDmaBuildBuffer);
    if (retCode != 0) {
        SASI_PAL_LOG_ERR("failed to RpmbBuildDataPtrFromDma for pDataIn 0x%x\n", retCode);
        symRc = retCode;
    }

processUnlockMutex:
    SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_PROC);

    if (SaSi_PalMutexUnlock(&sasiSymCryptoMutex) != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to release mutex\n");
    }
    return symRc;
}

int RpmbSymDriverAdaptorFinalize(struct drv_ctx_generic *pCtx, unsigned long *pListOfDataFrames, uint32_t listSize)
{
    DmaBuffer_s dmaBuffIn, dmaBuffOut;
    int symRc = SASI_RET_OK;
    uint32_t retCode;
    SaSi_PalPerfData_t perfIdx = 0;

    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_FIN);

    SASI_PAL_LOG_INFO("pCtx=%p\n", pCtx);
    SASI_PAL_LOG_INFO("IN addr=%p OUT addr=%p DataSize=%u\n", pDataIn, pDataOut, DataSize);

    retCode = SaSi_PalMutexLock(&sasiSymCryptoMutex, SASI_INFINITE);
    if (retCode != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }

    retCode =
        RpmbBuildDmaFromDataPtr(pListOfDataFrames, listSize, SASI_PAL_DMA_DIR_TO_DEVICE, &dmaBuffIn, &gDmaBuildBuffer);
    if (retCode != 0) {
        SASI_PAL_LOG_ERR("failed to RpmbBuildDmaFromDataPtr for pDataIn 0x%x\n", retCode);
        goto finalizeUnlockMutex;
    }

    symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_in, SASI_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx);
    if (symRc != SASI_RET_OK) {
        goto EndWithErr;
    }

    symRc = SymDriverDispatchFinalize(SASI_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, &dmaBuffIn, &dmaBuffOut);
    if (symRc != SASI_RET_OK) {
        goto EndWithErr;
    }

    WaitForSequenceCompletion();

    symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_out, SASI_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx);

EndWithErr:
    retCode = RpmbBuildDataPtrFromDma(pListOfDataFrames, listSize, SASI_PAL_DMA_DIR_TO_DEVICE, &gDmaBuildBuffer);
    if (retCode != 0) {
        SASI_PAL_LOG_ERR("failed to RpmbBuildDataPtrFromDma for pDataIn 0x%x\n", retCode);
        symRc = retCode;
    }

    SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_FIN);
finalizeUnlockMutex:
    if (SaSi_PalMutexUnlock(&sasiSymCryptoMutex) != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to release mutex\n");
    }
    return symRc;
}

int RpmbSymAdaptor2SasiHmacErr(int symRetCode, uint32_t errorInfo)
{
    SASI_UNUSED_PARAM(errorInfo); // remove compilation warning
    switch (symRetCode) {
    case SASI_RET_UNSUPP_ALG:
        return SaSi_HMAC_IS_NOT_SUPPORTED;
    case SASI_RET_UNSUPP_ALG_MODE:
    case SASI_RET_UNSUPP_OPERATION:
        return SaSi_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
    case SASI_RET_INVARG:
    case SASI_RET_INVARG_QID:
        return SaSi_HMAC_ILLEGAL_PARAMS_ERROR;
    case SASI_RET_INVARG_KEY_SIZE:
        return SaSi_HMAC_UNVALID_KEY_SIZE_ERROR;
    case SASI_RET_INVARG_CTX_IDX:
        return SaSi_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    case SASI_RET_INVARG_CTX:
        return SaSi_HMAC_USER_CONTEXT_CORRUPTED_ERROR;
    case SASI_RET_INVARG_BAD_ADDR:
        return SaSi_HMAC_DATA_IN_POINTER_INVALID_ERROR;
    case SASI_RET_NOMEM:
        return SaSi_OUT_OF_RESOURCE_ERROR;
    case SASI_RET_INVARG_INCONSIST_DMA_TYPE:
        return SaSi_ILLEGAL_RESOURCE_VAL_ERROR;
    case SASI_RET_PERM:
    case SASI_RET_NOEXEC:
    case SASI_RET_BUSY:
    case SASI_RET_OSFAULT:
    default:
        return SaSi_FATAL_ERROR;
    }
}

uint32_t RpmbBuildMlliTable(int j, uint32_t numOfBlocks, mlliTable_t *pDevBuffer,
                            RpmbDmaBuffBlocksInfo_t *pUsrBlockList)
{
    uint32_t i;
    SaSi_PalPerfData_t perfIdx = 0;

    if ((pDevBuffer == NULL) || (pUsrBlockList == NULL)) {
        return SASI_RET_INVARG;
    }
    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_MLLI_BUILD);

    /* fill mlli table entry */
    for (i = 0; i < numOfBlocks; i++) {
        /* set physical address of MLLI entry */
        LLI_SET_ADDR(pDevBuffer->pLliEntry[j].lliEntry, pUsrBlockList->pBlockEntry[i].blockPhysAddr);
        /* set size of MLLI entry */
        LLI_SET_SIZE(pDevBuffer->pLliEntry[j].lliEntry, pUsrBlockList->pBlockEntry[i].blockSize);

        pDevBuffer->pLliEntry[j].lliEntry[LLI_WORD0_OFFSET] =
            SET_WORD_LE(pDevBuffer->pLliEntry[j].lliEntry[LLI_WORD0_OFFSET]);
        pDevBuffer->pLliEntry[j].lliEntry[LLI_WORD1_OFFSET] =
            SET_WORD_LE(pDevBuffer->pLliEntry[j].lliEntry[LLI_WORD1_OFFSET]);

        SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_MLLI_BUILD);

        j++;
    }

    return 0;
}

uint32_t RpmbBuildDmaFromDataPtr(unsigned long *pListOfDataFrames, uint32_t listSize,
                                 SaSi_PalDmaBufferDirection_t direction, DmaBuffer_s *pDmaBuff,
                                 RpmbDmaBuildBuffer_t *pInterBuildBuff)
{
    uint32_t rc                            = 0;
    uint32_t numOfBlocks                   = 0;
    mlliTable_t *pDevBuffer                = NULL;
    RpmbDmaBuffBlocksInfo_t *pUsrBlockList = NULL;
    uint8_t *pUsrBuffer;
    uint32_t i, j;

    /* check inputs */
    if ((pInterBuildBuff == NULL) || (pDmaBuff == NULL)) {
        SASI_PAL_LOG_ERR("invalid parameters\n");
        return SASI_RET_INVARG;
    }
    if (listSize == 0) {
        SET_DMA_WITH_NULL(pDmaBuff);
        return 0;
    }

    j             = 0;
    pDevBuffer    = &pInterBuildBuff->devBuffer;
    pUsrBlockList = &pInterBuildBuff->blocksList;

    for (i = 0; i < listSize; i++) {
        pUsrBuffer                    = (uint8_t *)(pListOfDataFrames[i]);
        pUsrBlockList->numOfBlocks[i] = RPMB_MAX_PAGES_PER_BLOCK; // assert max of 2 pages

        /* check if buffer is NULL, skip to error case */
        if (pUsrBuffer == NULL) {
            rc = SASI_RET_NOMEM;
            goto endError_unMapDmaBuffer;
        }

        rc = SaSi_PalDmaBufferMap((uint8_t *)pUsrBuffer, SASI_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES, direction,
                                  &pUsrBlockList->numOfBlocks[i], pUsrBlockList->pBlockEntry,
                                  &pInterBuildBuff->buffMainH[i]);

        if (rc != 0) {
            SASI_PAL_LOG_ERR("failed to SaSi_PalDmaBufferMap for user buffer %d\n", i);
            goto endError_unMapDmaBuffer;
        }

        /* returned numOfBlocks should be either 1 or 2 */
        if (pUsrBlockList->numOfBlocks[i] > RPMB_MAX_PAGES_PER_BLOCK) {
            SASI_PAL_LOG_ERR("failed to SaSi_PalDmaBufferMap for user buffer %d\n", i);
            rc = SASI_RET_OSFAULT;
            i++;
            goto endError_unMapDmaBuffer;
        }

        /* add block entry to MLLI table */
        RpmbBuildMlliTable(j, pUsrBlockList->numOfBlocks[i], pDevBuffer, pUsrBlockList);

        j += pUsrBlockList->numOfBlocks[i];
    }

    /* in order to use the hash driver as is, add dummy tail entry */
    pDevBuffer->mlliBlockInfo.blockSize = (j + 1) * sizeof(lliInfo_t);

    /* map MLLI table */
    numOfBlocks = SINGLE_BLOCK_ENTRY;
    rc          = SaSi_PalDmaBufferMap((uint8_t *)pDevBuffer->pLliEntry, pDevBuffer->mlliBlockInfo.blockSize,
                              SASI_PAL_DMA_DIR_BI_DIRECTION, &numOfBlocks, &pDevBuffer->mlliBlockInfo,
                              &pInterBuildBuff->buffMlliH);
    if (rc != 0) {
        SASI_PAL_LOG_ERR("failed to SaSi_PalDmaBufferMap for mlli table 0x%x\n", rc);
        goto endError_unMapDmaBuffer;
    }
    /* in case numOfBlocks returned bigger than 1, we declare error */
    if (numOfBlocks > SINGLE_BLOCK_ENTRY) {
        SASI_PAL_LOG_ERR("failed to SaSi_PalDmaBufferMap for mlli numOfBlocks > 1\n");
        rc = SASI_RET_OSFAULT;
        goto endError_unMapMlliBuffer;
    }
    SET_DMA_WITH_MLLI(pDmaBuff, pDevBuffer->mlliBlockInfo.blockPhysAddr, pDevBuffer->mlliBlockInfo.blockSize);
    return 0;

endError_unMapMlliBuffer:
    SaSi_PalDmaBufferUnmap((uint8_t *)pDevBuffer->pLliEntry, pDevBuffer->mlliBlockInfo.blockSize,
                           SASI_PAL_DMA_DIR_BI_DIRECTION, SINGLE_BLOCK_ENTRY, &pDevBuffer->mlliBlockInfo,
                           pInterBuildBuff->buffMlliH);

endError_unMapDmaBuffer:
    /* i holds the number of buffers that should be unmapped */
    for (j = 0; j < i; j++) {
        pUsrBuffer = (uint8_t *)(pListOfDataFrames[j]);

        /* check if buffer is NULL, skip to next buffer */
        if (pUsrBuffer == NULL)
            continue;

        /* unmap the buffer */
        SaSi_PalDmaBufferUnmap((uint8_t *)pUsrBuffer, SASI_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES, direction,
                               pUsrBlockList->numOfBlocks[j], pUsrBlockList->pBlockEntry,
                               pInterBuildBuff->buffMainH[j]);
    }

    return rc;
}

uint32_t RpmbBuildDataPtrFromDma(unsigned long *pListOfDataFrames, uint32_t listSize,
                                 SaSi_PalDmaBufferDirection_t direction, RpmbDmaBuildBuffer_t *pInterBuildBuff)
{
    uint32_t rc                            = 0;
    mlliTable_t *pDevBuffer                = NULL;
    RpmbDmaBuffBlocksInfo_t *pUsrBlockList = NULL;
    uint8_t *pUsrBuffer;
    uint32_t i;

    /* check inputs */
    if (pInterBuildBuff == NULL) {
        SASI_PAL_LOG_ERR("invalid parameters\n");
        return SASI_RET_INVARG;
    }

    if (listSize == 0) {
        return 0;
    }

    pDevBuffer    = &pInterBuildBuff->devBuffer;
    pUsrBlockList = &pInterBuildBuff->blocksList;

    for (i = 0; i < listSize; i++) {
        pUsrBuffer = (uint8_t *)(pListOfDataFrames[i]);

        /* check if buffer is NULL, skip to next buffer */
        if (pUsrBuffer == NULL)
            continue;

        /* unmap the buffer */
        rc |= SaSi_PalDmaBufferUnmap((uint8_t *)pUsrBuffer, SASI_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES, direction,
                                     pUsrBlockList->numOfBlocks[i], pUsrBlockList->pBlockEntry,
                                     pInterBuildBuff->buffMainH[i]);
    }

    /* Unmap MLLI */
    rc |= SaSi_PalDmaBufferUnmap((uint8_t *)pDevBuffer->pLliEntry, pDevBuffer->mlliBlockInfo.blockSize,
                                 SASI_PAL_DMA_DIR_BI_DIRECTION, SINGLE_BLOCK_ENTRY, &pDevBuffer->mlliBlockInfo,
                                 pInterBuildBuff->buffMlliH);

    if (rc != 0) {
        rc = SASI_RET_BUSY;
    }

    return rc;
}

void RpmbClearDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff)
{
    if (pDmaBuildBuff == NULL) {
        return;
    }
    SaSi_PalMemSetZero(pDmaBuildBuff->blocksList.pBlockEntry,
                       RPMB_MAX_PAGES_PER_BLOCK * sizeof(SaSi_PalDmaBlockInfo_t));
    SaSi_PalMemSetZero(pDmaBuildBuff->blocksList.numOfBlocks, RPMB_MAX_BLOCKS_PER_UPDATE * sizeof(uint32_t));

    SaSi_PalMemSetZero((uint8_t *)&pDmaBuildBuff->devBuffer.mlliBlockInfo, sizeof(SaSi_PalDmaBlockInfo_t));

    if (pDmaBuildBuff->devBuffer.pLliEntry != NULL) {
        SaSi_PalMemSetZero(pDmaBuildBuff->devBuffer.pLliEntry, FW_MLLI_TABLE_LEN * sizeof(lliInfo_t));
    }
}

void RpmbFreeDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff)
{
    if (pDmaBuildBuff == NULL) {
        return;
    }
    if (pDmaBuildBuff->devBuffer.pLliEntry != NULL) {
        SaSi_PalDmaContigBufferFree(FW_MLLI_TABLE_LEN * sizeof(lliInfo_t),
                                    (uint8_t *)pDmaBuildBuff->devBuffer.pLliEntry);
        pDmaBuildBuff->devBuffer.pLliEntry = NULL;
    }
}

uint32_t RpmbAllocDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff)
{
    uint32_t rc      = 0;
    uint8_t *tmpBuff = NULL;

    if (pDmaBuildBuff == NULL) {
        return SASI_RET_INVARG;
    }
    tmpBuff = (uint8_t *)pDmaBuildBuff->devBuffer.pLliEntry;
    rc      = SaSi_PalDmaContigBufferAllocate(FW_MLLI_TABLE_LEN * sizeof(lliInfo_t), &tmpBuff);
    if (rc != 0) {
        return SASI_RET_NOMEM;
    }
    if (!IS_ALIGNED((unsigned long)tmpBuff, 4))
        return SASI_RET_INVARG_BAD_ADDR;

    /* casting to void to avoid compilation error , address must be aligned to word , otherwise an error will return */
    pDmaBuildBuff->devBuffer.pLliEntry = (lliInfo_t *)((void *)tmpBuff);

    RpmbClearDmaBuildBuffers(pDmaBuildBuff);

    return SASI_RET_OK;
}
