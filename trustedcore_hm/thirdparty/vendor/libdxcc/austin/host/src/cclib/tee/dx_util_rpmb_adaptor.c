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
#include "crys_context_relocation.h"
#include "dx_sram_map.h"
#include "crys_hmac.h"
#include "crys_hmac_error.h"
#include "cc_plat.h"
#include "dx_pal_mem.h"
#include "dx_pal_perf.h"
#include "dx_pal_log.h"
#include "dx_pal_dma.h"
#include "dx_pal_abort.h"
#include "dx_pal_mutex.h"
#include "dx_util_rpmb_adaptor.h"
#include "dma_buffer.h"
#include "sym_adaptor_driver_int.h"
#include "sym_crypto_driver.h"
#include "completion.h"
#include "cc_plat.h"

// #include <assert.h>

/* *********************** Statics **************************** */
static RpmbDmaBuildBuffer_t gDmaBuildBuffer;

int RpmbSymDriverAdaptorModuleInit()
{
    int symRc = DX_RET_OK;

    /* allocate internal buffer for dma device resources */
    symRc = RpmbAllocDmaBuildBuffers(&gDmaBuildBuffer);

    if (symRc != DX_RET_OK) {
        symRc = DX_RET_NOMEM;
    }

    return symRc;
}

int RpmbSymDriverAdaptorModuleTerminate()
{
    /* release internal dma buffer resources */
    RpmbFreeDmaBuildBuffers(&gDmaBuildBuffer);

    return DX_RET_OK;
}

DxError_t RpmbHmacUpdate(CRYS_HMACUserContext_t *ContextID_ptr, unsigned long *pListOfDataFrames, uint32_t listSize)
{
    struct sep_ctx_hmac *pHmacContext;
    CRYS_HMACPrivateContext_t *pHmacPrivContext;
    int symRc = DX_RET_OK;

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct sep_ctx_hmac *)DX_GetUserCtxLocation(ContextID_ptr->buff, sizeof(CRYS_HMACUserContext_t));
    if (pHmacContext == NULL)
        return CRYS_HMAC_ILLEGAL_PARAMS_ERROR;

    pHmacPrivContext =
        (CRYS_HMACPrivateContext_t *)&(((uint32_t *)pHmacContext)[CRYS_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    if (listSize == RPMB_MAX_BLOCKS_PER_UPDATE) {
        symRc = RpmbSymDriverAdaptorProcess((struct sep_ctx_generic *)pHmacContext, pListOfDataFrames, listSize);
        if (symRc != DX_RET_OK) {
            return DX_CRYS_RETURN_ERROR(symRc, 0, RpmbSymAdaptor2CrysHmacErr);
        }
    } else { /* this is the last block */
        pHmacPrivContext->isLastBlockProcessed = 1;
        symRc = RpmbSymDriverAdaptorFinalize((struct sep_ctx_generic *)pHmacContext, pListOfDataFrames, listSize);
        if (symRc != DX_RET_OK) {
            return DX_CRYS_RETURN_ERROR(symRc, 0, RpmbSymAdaptor2CrysHmacErr);
        }
    }

    if (symRc != DX_RET_OK) {
        return DX_CRYS_RETURN_ERROR(symRc, 0, RpmbSymAdaptor2CrysHmacErr);
    }

    return CRYS_OK;
}

DxError_t RpmbHmacFinish(CRYS_HMACUserContext_t *ContextID_ptr, CRYS_HASH_Result_t HmacResultBuff)
{
    struct sep_ctx_hmac *pHmacContext;
    CRYS_HMACPrivateContext_t *pHmacPrivContext;
    int symRc = DX_RET_OK;

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct sep_ctx_hmac *)DX_GetUserCtxLocation(ContextID_ptr->buff, sizeof(CRYS_HMACUserContext_t));
    if (pHmacContext == NULL)
        return CRYS_HMAC_ILLEGAL_PARAMS_ERROR;

    pHmacPrivContext =
        (CRYS_HMACPrivateContext_t *)&(((uint32_t *)pHmacContext)[CRYS_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    if (pHmacPrivContext->isLastBlockProcessed == 0) {
        symRc = RpmbSymDriverAdaptorFinalize((struct sep_ctx_generic *)pHmacContext, NULL, 0);
        if (symRc != DX_RET_OK) {
            return DX_CRYS_RETURN_ERROR(symRc, 0, RpmbSymAdaptor2CrysHmacErr);
        }
    }

    DX_PAL_MemCopy(HmacResultBuff, pHmacContext->digest, SEP_SHA256_DIGEST_SIZE);
    return CRYS_OK;
}

int RpmbSymDriverAdaptorProcess(struct sep_ctx_generic *pCtx, unsigned long *pListOfDataFrames, uint32_t listSize)
{
    int symRc = DX_RET_OK;
    DmaBuffer_s dmaBuffIn;
    DmaBuffer_s dmaBuffOut;
    uint32_t retCode;
    DX_PAL_PerfData_t perfIdx = 0;

    DX_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_PROC);
    DX_PAL_LOG_INFO("pCtx=%p\n", pCtx);
    DX_PAL_LOG_INFO("IN addr=%p OUT addr=%p DataSize=%u\n", pDataIn, pDataOut, DataSize);

    retCode = DX_PAL_MutexLock(&dxSymCryptoMutex, DX_INFINITE);
    if (retCode != DX_SUCCESS) {
        DX_PAL_Abort("Fail to acquire mutex\n");
    }

    retCode =
        RpmbBuildDmaFromDataPtr(pListOfDataFrames, listSize, DX_PAL_DMA_DIR_TO_DEVICE, &dmaBuffIn, &gDmaBuildBuffer);
    if (retCode != 0) {
        DX_PAL_LOG_ERR("failed to RpmbBuildDmaFromDataPtr for pDataIn 0x%x\n", retCode);
        symRc = retCode;
        goto processUnlockMutex;
    }

    symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_in, DX_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx);
    if (symRc != DX_RET_OK) {
        goto EndWithErr;
    }

    symRc = SymDriverDispatchProcess(DX_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, &dmaBuffIn, &dmaBuffOut);
    if (symRc != DX_RET_OK) {
        goto EndWithErr;
    }

    WaitForSequenceCompletion();
    symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_out, DX_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx);

EndWithErr:

    retCode =
        RpmbBuildDataPtrFromDma(pListOfDataFrames, listSize, DX_PAL_DMA_DIR_TO_DEVICE, &dmaBuffIn, &gDmaBuildBuffer);
    if (retCode != 0) {
        DX_PAL_LOG_ERR("failed to RpmbBuildDataPtrFromDma for pDataIn 0x%x\n", retCode);
        symRc = retCode;
    }

processUnlockMutex:
    DX_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_PROC);

    if (DX_PAL_MutexUnlock(&dxSymCryptoMutex) != DX_SUCCESS) {
        DX_PAL_Abort("Fail to release mutex\n");
    }
    return symRc;
}

int RpmbSymDriverAdaptorFinalize(struct sep_ctx_generic *pCtx, unsigned long *pListOfDataFrames, uint32_t listSize)
{
    DmaBuffer_s dmaBuffIn, dmaBuffOut;
    int symRc = DX_RET_OK;
    uint32_t retCode;
    DX_PAL_PerfData_t perfIdx = 0;

    DX_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_FIN);

    DX_PAL_LOG_INFO("pCtx=%p\n", pCtx);
    DX_PAL_LOG_INFO("IN addr=%p OUT addr=%p DataSize=%u\n", pDataIn, pDataOut, DataSize);

    retCode = DX_PAL_MutexLock(&dxSymCryptoMutex, DX_INFINITE);
    if (retCode != DX_SUCCESS) {
        DX_PAL_Abort("Fail to acquire mutex\n");
    }

    retCode =
        RpmbBuildDmaFromDataPtr(pListOfDataFrames, listSize, DX_PAL_DMA_DIR_TO_DEVICE, &dmaBuffIn, &gDmaBuildBuffer);
    if (retCode != 0) {
        DX_PAL_LOG_ERR("failed to RpmbBuildDmaFromDataPtr for pDataIn 0x%x\n", retCode);
        goto finalizeUnlockMutex;
    }

    symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_in, DX_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx);
    if (symRc != DX_RET_OK) {
        goto EndWithErr;
    }

    symRc = SymDriverDispatchFinalize(DX_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, &dmaBuffIn, &dmaBuffOut);
    if (symRc != DX_RET_OK) {
        goto EndWithErr;
    }

    WaitForSequenceCompletion();

    symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_out, DX_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx);

EndWithErr:
    retCode =
        RpmbBuildDataPtrFromDma(pListOfDataFrames, listSize, DX_PAL_DMA_DIR_TO_DEVICE, &dmaBuffIn, &gDmaBuildBuffer);
    if (retCode != 0) {
        DX_PAL_LOG_ERR("failed to RpmbBuildDataPtrFromDma for pDataIn 0x%x\n", retCode);
        symRc = retCode;
    }

    DX_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_FIN);
finalizeUnlockMutex:
    if (DX_PAL_MutexUnlock(&dxSymCryptoMutex) != DX_SUCCESS) {
        DX_PAL_Abort("Fail to release mutex\n");
    }
    return symRc;
}

int RpmbSymAdaptor2CrysHmacErr(int symRetCode, uint32_t errorInfo)
{
    switch (symRetCode) {
    case DX_RET_UNSUPP_ALG:
        return CRYS_HMAC_IS_NOT_SUPPORTED;
    case DX_RET_UNSUPP_ALG_MODE:
    case DX_RET_UNSUPP_OPERATION:
        return CRYS_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
    case DX_RET_INVARG:
    case DX_RET_INVARG_QID:
        return CRYS_HMAC_ILLEGAL_PARAMS_ERROR;
    case DX_RET_INVARG_KEY_SIZE:
        return CRYS_HMAC_UNVALID_KEY_SIZE_ERROR;
    case DX_RET_INVARG_CTX_IDX:
        return CRYS_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    case DX_RET_INVARG_CTX:
        return CRYS_HMAC_USER_CONTEXT_CORRUPTED_ERROR;
    case DX_RET_INVARG_BAD_ADDR:
        return CRYS_HMAC_DATA_IN_POINTER_INVALID_ERROR;
    case DX_RET_NOMEM:
        return CRYS_OUT_OF_RESOURCE_ERROR;
    case DX_RET_INVARG_INCONSIST_DMA_TYPE:
        return CRYS_ILLEGAL_RESOURCE_VAL_ERROR;
    case DX_RET_PERM:
    case DX_RET_NOEXEC:
    case DX_RET_BUSY:
    case DX_RET_OSFAULT:
    default:
        return CRYS_FATAL_ERROR;
    }
}

uint32_t RpmbBuildMlliTable(int j, uint32_t numOfBlocks, mlliTable_t *pDevBuffer,
                            RpmbDmaBuffBlocksInfo_t *pUsrBlockList)
{
    uint32_t i;
    DX_PAL_PerfData_t perfIdx = 0;

    if ((pDevBuffer == NULL) || (pUsrBlockList == NULL)) {
        return DX_RET_INVARG;
    }
    DX_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_MLLI_BUILD);

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

        DX_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_MLLI_BUILD);

        j++;
    }

    return 0;
}

uint32_t RpmbBuildDmaFromDataPtr(unsigned long *pListOfDataFrames, uint32_t listSize,
                                 DX_PAL_DmaBufferDirection_t direction, DmaBuffer_s *pDmaBuff,
                                 RpmbDmaBuildBuffer_t *pInterBuildBuff)
{
    uint32_t rc                            = 0;
    uint32_t numOfBlocks                   = 0;
    mlliTable_t *pDevBuffer                = NULL;
    RpmbDmaBuffBlocksInfo_t *pUsrBlockList = NULL;
    uint8_t *pUsrBuffer;
    int i, j;

    /* check inputs */
    if ((pInterBuildBuff == NULL) || (pDmaBuff == NULL)) {
        DX_PAL_LOG_ERR("invalid parameters\n");
        return DX_RET_INVARG;
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
            rc = DX_RET_NOMEM;
            goto endError_unMapDmaBuffer;
        }

        rc = DX_PAL_DmaBufferMap((uint8_t *)pUsrBuffer, DX_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES, direction,
                                 &pUsrBlockList->numOfBlocks[i], pUsrBlockList->pBlockEntry,
                                 &pInterBuildBuff->buffMainH[i]);

        if (rc != 0) {
            DX_PAL_LOG_ERR("failed to DX_PAL_DmaBufferMap for user buffer %d\n", i);
            goto endError_unMapDmaBuffer;
        }

        /* returned numOfBlocks should be either 1 or 2 */
        if (pUsrBlockList->numOfBlocks[i] > RPMB_MAX_PAGES_PER_BLOCK) {
            DX_PAL_LOG_ERR("failed to DX_PAL_DmaBufferMap for user buffer %d\n", i);
            rc = DX_RET_OSFAULT;
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
    rc          = DX_PAL_DmaBufferMap((uint8_t *)pDevBuffer->pLliEntry, pDevBuffer->mlliBlockInfo.blockSize,
                             DX_PAL_DMA_DIR_BI_DIRECTION, &numOfBlocks, &pDevBuffer->mlliBlockInfo,
                             &pInterBuildBuff->buffMlliH);
    if (rc != 0) {
        DX_PAL_LOG_ERR("failed to DX_PAL_DmaBufferMap for mlli table 0x%x\n", rc);
        goto endError_unMapDmaBuffer;
    }
    /* in case numOfBlocks returned bigger than 1, we declare error */
    if (numOfBlocks > SINGLE_BLOCK_ENTRY) {
        DX_PAL_LOG_ERR("failed to DX_PAL_DmaBufferMap for mlli numOfBlocks > 1\n");
        rc = DX_RET_OSFAULT;
        goto endError_unMapMlliBuffer;
    }
    SET_DMA_WITH_MLLI(pDmaBuff, pDevBuffer->mlliBlockInfo.blockPhysAddr, pDevBuffer->mlliBlockInfo.blockSize);
    return 0;

endError_unMapMlliBuffer:
    DX_PAL_DmaBufferUnmap((uint8_t *)pDevBuffer->pLliEntry, pDevBuffer->mlliBlockInfo.blockSize,
                          DX_PAL_DMA_DIR_BI_DIRECTION, SINGLE_BLOCK_ENTRY, &pDevBuffer->mlliBlockInfo,
                          pInterBuildBuff->buffMlliH);

endError_unMapDmaBuffer:
    /* i holds the number of buffers that should be unmapped */
    for (j = 0; j < i; j++) {
        pUsrBuffer = (uint8_t *)(pListOfDataFrames[j]);

        /* check if buffer is NULL, skip to next buffer */
        if (pUsrBuffer == NULL)
            continue;

        /* unmap the buffer */
        DX_PAL_DmaBufferUnmap((uint8_t *)pUsrBuffer, DX_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES, direction,
                              pUsrBlockList->numOfBlocks[j], pUsrBlockList->pBlockEntry, pInterBuildBuff->buffMainH[j]);
    }

    return rc;
}

uint32_t RpmbBuildDataPtrFromDma(unsigned long *pListOfDataFrames, uint32_t listSize,
                                 DX_PAL_DmaBufferDirection_t direction, DmaBuffer_s *pDmaBuff,
                                 RpmbDmaBuildBuffer_t *pInterBuildBuff)
{
    uint32_t rc                            = 0;
    mlliTable_t *pDevBuffer                = NULL;
    RpmbDmaBuffBlocksInfo_t *pUsrBlockList = NULL;
    uint8_t *pUsrBuffer;
    int i;

    /* check inputs */
    if (pInterBuildBuff == NULL) {
        DX_PAL_LOG_ERR("invalid parameters\n");
        return DX_RET_INVARG;
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
        rc |= DX_PAL_DmaBufferUnmap((uint8_t *)pUsrBuffer, DX_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES, direction,
                                    pUsrBlockList->numOfBlocks[i], pUsrBlockList->pBlockEntry,
                                    pInterBuildBuff->buffMainH[i]);
    }

    /* Unmap MLLI */
    rc |= DX_PAL_DmaBufferUnmap((uint8_t *)pDevBuffer->pLliEntry, pDevBuffer->mlliBlockInfo.blockSize,
                                DX_PAL_DMA_DIR_BI_DIRECTION, SINGLE_BLOCK_ENTRY, &pDevBuffer->mlliBlockInfo,
                                pInterBuildBuff->buffMlliH);

    if (rc != 0) {
        rc = DX_RET_BUSY;
    }

    return rc;
}

void RpmbClearDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff)
{
    if (pDmaBuildBuff == NULL) {
        return;
    }
    DX_PAL_MemSetZero(pDmaBuildBuff->blocksList.pBlockEntry, RPMB_MAX_PAGES_PER_BLOCK * sizeof(DX_PAL_DmaBlockInfo_t));
    DX_PAL_MemSetZero(pDmaBuildBuff->blocksList.numOfBlocks, RPMB_MAX_BLOCKS_PER_UPDATE * sizeof(uint32_t));

    DX_PAL_MemSetZero((uint8_t *)&pDmaBuildBuff->devBuffer.mlliBlockInfo, sizeof(DX_PAL_DmaBlockInfo_t));

    if (pDmaBuildBuff->devBuffer.pLliEntry != NULL) {
        DX_PAL_MemSetZero(pDmaBuildBuff->devBuffer.pLliEntry, FW_MLLI_TABLE_LEN * sizeof(lliInfo_t));
    }
}

void RpmbFreeDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff)
{
    if (pDmaBuildBuff == NULL) {
        return;
    }
    if (pDmaBuildBuff->devBuffer.pLliEntry != NULL) {
        DX_PAL_DmaContigBufferFree(FW_MLLI_TABLE_LEN * sizeof(lliInfo_t),
                                   (uint8_t *)pDmaBuildBuff->devBuffer.pLliEntry);
        pDmaBuildBuff->devBuffer.pLliEntry = NULL;
    }
}

uint32_t RpmbAllocDmaBuildBuffers(RpmbDmaBuildBuffer_t *pDmaBuildBuff)
{
    uint32_t rc      = 0;
    uint8_t *tmpBuff = NULL;

    if (pDmaBuildBuff == NULL) {
        return DX_RET_INVARG;
    }
    tmpBuff = (uint8_t *)pDmaBuildBuff->devBuffer.pLliEntry;
    rc      = DX_PAL_DmaContigBufferAllocate(FW_MLLI_TABLE_LEN * sizeof(lliInfo_t), &tmpBuff);

    if (rc != 0) {
        return DX_RET_NOMEM;
    }
    pDmaBuildBuff->devBuffer.pLliEntry = (lliInfo_t *)tmpBuff;

    RpmbClearDmaBuildBuffers(pDmaBuildBuff);

    return DX_RET_OK;
}
