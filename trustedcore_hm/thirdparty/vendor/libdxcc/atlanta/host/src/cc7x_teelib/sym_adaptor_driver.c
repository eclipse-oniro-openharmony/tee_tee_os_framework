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
#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_SYM_DRIVER

#include "cc_pal_types.h"
#include "cc_plat.h"
#include "cc_pal_mem.h"
#include "cc_pal_dma.h"
#include "cc_pal_log.h"
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "cc_sym_error.h"
#include "cc_plat.h"
#include "cc_crypto_ctx.h"
#include "completion.h"
#include "cc_pal_perf.h"
#include "sym_crypto_driver.h"
#include "sym_adaptor_driver.h"
#include "sym_adaptor_driver_int.h"
#include "cc_sram_map.h"
#include "cc_hal.h"


static interDmaBuildBuffer_t g_dmaInBuildBuffH;  // internal buffer for dma, built for to device or bi-directional
static interDmaBuildBuffer_t g_dmaOutBuildBuffH;   // internal buffer for dma, built for from device

extern CC_PalMutex CCSymCryptoMutex;

#define MAX_DLLI_BLOCK_SIZE  ((1<<25)-1)  // has 24 bits for size
#define MAX_MLLI_ENTRY_SIZE  ((1<<17)-1) // has 16 bits for size

/******************************************************************************
*				PRIVATE FUNCTIONS
******************************************************************************/

/*!
 * The function returns the context size according to the algorithem type
 *
 *
 * \param pCtx
 *
 * \return int The size of the context in bytes.
 */
static int SymDriverAdaptorGetCtxSize(enum drv_crypto_alg alg)
{
	uint32_t ctxSize; /*size in words*/

	switch (alg){
		case DRV_CRYPTO_ALG_DES:
		case DRV_CRYPTO_ALG_AES:
			/* copied fields block_state + key + xex_key */
			ctxSize = CC_AES_BLOCK_SIZE + CC_AES_KEY_SIZE_MAX + CC_AES_KEY_SIZE_MAX;
			break;
		case DRV_CRYPTO_ALG_HMAC:
			/* digest + k0 size + CurrentDigestedLength */
			ctxSize = CC_DIGEST_SIZE_MAX + CC_HMAC_BLOCK_SIZE_MAX+DRV_HASH_LENGTH_WORDS*sizeof(uint32_t);
            break;
		case DRV_CRYPTO_ALG_HASH:
			/* digest + CurrentDigestedLength */
			ctxSize = CC_DIGEST_SIZE_MAX + DRV_HASH_LENGTH_WORDS*sizeof(uint32_t);
			break;
			ctxSize = sizeof(struct drv_ctx_hash);
			break;
		case DRV_CRYPTO_ALG_BYPASS:
			ctxSize = sizeof(uint32_t);
			break;
		case DRV_CRYPTO_ALG_AEAD:
			/* block_state + mac_state + key */
			ctxSize = CC_AES_BLOCK_SIZE + CC_AES_BLOCK_SIZE + CC_AES_KEY_SIZE_MAX;
			break;
		default:
			ctxSize = 0;
		break;
	}
	return ctxSize;
}

static void clearDmaBuildBuffers(interDmaBuildBuffer_t *pDmaBuildBuff)
{
	if (NULL == pDmaBuildBuff) {
		return;
	}
	CC_PalMemSetZero(pDmaBuildBuff->blocksList.pBlockEntry, FW_MLLI_TABLE_LEN * sizeof(CCPalDmaBlockInfo_t));
	pDmaBuildBuff->blocksList.numOfBlocks = 0;

	CC_PalMemSetZero((uint8_t *)&pDmaBuildBuff->devBuffer.mlliBlockInfo, sizeof(CCPalDmaBlockInfo_t));

	if (pDmaBuildBuff->tailBuff.pVirtBuffer != NULL) {
		CC_PalMemSetZero(pDmaBuildBuff->tailBuff.pVirtBuffer, MAX_TAIL_BUFF_SIZE);
	}
	if (pDmaBuildBuff->devBuffer.pLliEntry != NULL) {
		CC_PalMemSetZero(pDmaBuildBuff->devBuffer.pLliEntry, FW_MLLI_TABLE_LEN * sizeof(lliInfo_t));
	}
}


static void freeDmaBuildBuffers(interDmaBuildBuffer_t *pDmaBuildBuff)
{
	if (NULL == pDmaBuildBuff) {
		return;
	}
	if (pDmaBuildBuff->tailBuff.pVirtBuffer != NULL) {
		CC_PalDmaContigBufferFree(MAX_TAIL_BUFF_SIZE, pDmaBuildBuff->tailBuff.pVirtBuffer);
		pDmaBuildBuff->tailBuff.pVirtBuffer = NULL;
	}
	if (pDmaBuildBuff->devBuffer.pLliEntry != NULL) {
		CC_PalDmaContigBufferFree(FW_MLLI_TABLE_LEN * sizeof(lliInfo_t), (uint8_t *)pDmaBuildBuff->devBuffer.pLliEntry);
		pDmaBuildBuff->devBuffer.pLliEntry = NULL;
	}
}

uint32_t allocDmaBuildBuffers(interDmaBuildBuffer_t *pDmaBuildBuff)
{
	uint32_t rc = 0;
	uint8_t *tmpBuff = NULL;

	if (NULL == pDmaBuildBuff) {
		return CC_RET_INVARG;
	}
	tmpBuff = (uint8_t *)pDmaBuildBuff->devBuffer.pLliEntry;
	rc = CC_PalDmaContigBufferAllocate(FW_MLLI_TABLE_LEN * sizeof(lliInfo_t),
					    &tmpBuff);
	if (rc != 0) {
		return CC_RET_NOMEM;
	}
	if (!IS_ALIGNED((unsigned long)tmpBuff, 4))
		return CC_RET_INVARG_BAD_ADDR;

	/* casting to void to avoid compilation error , address must be aligned to word , otherwise an error will return */
	pDmaBuildBuff->devBuffer.pLliEntry = (lliInfo_t *)((void*)tmpBuff);

	rc = CC_PalDmaContigBufferAllocate(MAX_TAIL_BUFF_SIZE,
			                   &pDmaBuildBuff->tailBuff.pVirtBuffer);
	if (rc != 0) {
		freeDmaBuildBuffers(pDmaBuildBuff);
		return CC_RET_NOMEM;
	}
	clearDmaBuildBuffers(pDmaBuildBuff);
	return CC_RET_OK;
}


/**
 * @brief   fills mlli entries based on physical addresses and sizes from blockList
 *
 *
 * @param[in] pUsrBlockList - list of blocks
 * @param[out] pDevBuffer - mlli list to fill
 *
 * @return success/fail
 */
static uint32_t   buildMlliTable(mlliTable_t *pDevBuffer, dmaBuffBlocksInfo_t *pUsrBlockList)
{
	uint32_t	i = 0;
	uint32_t	mlliEntries = 0;
	CCPalPerfData_t 	perfIdx = 0;

	if ((NULL == pDevBuffer) ||
	    (NULL == pUsrBlockList)) {
		return CC_RET_INVARG;
	}
	// mlli table has 1 additional entries compares to pUsrBlockList->numOfBlocks:
	// last entry is tail 32 bytes length
	mlliEntries = pUsrBlockList->numOfBlocks+1;
	// calculate mlli table size,
	pDevBuffer->mlliBlockInfo.blockSize = mlliEntries*sizeof(lliInfo_t);
	CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_MLLI_BUILD);

	// fill other mlli table entries. Note that pUsrBlockList->pBlockEntry
	// has no dummy entry, therefor its indexes are (i-1)
	for (i = 0; i < mlliEntries; i++) {
		// Verify blockSize is not bigger than MLLI can bug #11694
		if (pUsrBlockList->pBlockEntry[i].blockSize > MAX_MLLI_ENTRY_SIZE) {
			CC_PalMemSetZero(pDevBuffer->pLliEntry, FW_MLLI_TABLE_LEN * sizeof(lliInfo_t));
			return 1;
		}
		// set physical address of MLLI entry
		LLI_SET_ADDR(pDevBuffer->pLliEntry[i].lliEntry, pUsrBlockList->pBlockEntry[i].blockPhysAddr);
		// set size of MLLI entry
		LLI_SET_SIZE(pDevBuffer->pLliEntry[i].lliEntry, pUsrBlockList->pBlockEntry[i].blockSize);

		// copy lliEntry to MLLI table - LE/BE must be considered
		pDevBuffer->pLliEntry[i].lliEntry[LLI_WORD0_OFFSET] =
			SET_WORD_LE(pDevBuffer->pLliEntry[i].lliEntry[LLI_WORD0_OFFSET]);
		pDevBuffer->pLliEntry[i].lliEntry[LLI_WORD1_OFFSET] =
			SET_WORD_LE(pDevBuffer->pLliEntry[i].lliEntry[LLI_WORD1_OFFSET]);
	}
	CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_MLLI_BUILD);
	return 0;
}

/**
 * @brief   sets user buffer into dma buffer to be used by HW
 *
 *
 * @param[in] pUsrBuffer - address of the buffer allocated by user
 * @param[in] usrBuffSize - data direction: into device, from device or bidirectional
 * @param[in] direction - bi-directional/to/from device
 * @param[out] pDmaBuff - dma buffer to be used by HW
 * @param[out] pInterBuildBuff - mlli list,  page list abd cookies used to build the dms bufffer
 *
 * @return success/fail
 */
static uint32_t buildDmaFromDataPtr(uint8_t *pUsrBuffer,
				    size_t usrBuffSize,
				    CCPalDmaBufferDirection_t direction,
				    DmaBuffer_s *pDmaBuff,
				    interDmaBuildBuffer_t *pInterBuildBuff)
{
	uint32_t		rc = 0;
	uint32_t 		numOfBlocks = 0;
	mlliTable_t 		*pDevBuffer = NULL;
	dmaBuffBlocksInfo_t   	*pUsrBlockList = NULL;
	tailBuffInfo_t		*pTailBuff = NULL;
	uint32_t		errorClearFlag = 0;

	// check inputs
	if ((NULL == pInterBuildBuff) ||
	    (NULL == pDmaBuff)) {
		CC_PAL_LOG_ERR("invalid parameters\n");
		return CC_RET_INVARG;
	}

	// first check if buffer is NULL, build simple empty dma buffer
	if ((NULL == pUsrBuffer) ||
	    (0 == usrBuffSize)) {
		SET_DMA_WITH_NULL(pDmaBuff);
		return 0;
	}

	pDevBuffer = &pInterBuildBuff->devBuffer;
	pUsrBlockList = &pInterBuildBuff->blocksList;
	pTailBuff = &pInterBuildBuff->tailBuff;
	pUsrBlockList->numOfBlocks = (FW_MLLI_TABLE_LEN - 1);

	// second case, if buffer is contiguous build DLLI
	if (CC_PalIsDmaBufferContiguous(pUsrBuffer, usrBuffSize)) {
		// Verify size of max DLLI
		if (usrBuffSize > MAX_DLLI_BLOCK_SIZE) {
			return CC_RET_NOMEM;
		}
		pUsrBlockList->numOfBlocks = SINGLE_BLOCK_ENTRY;
		rc = CC_PalDmaBufferMap((uint8_t *)pUsrBuffer,
					  usrBuffSize,
					  direction,
					  &pUsrBlockList->numOfBlocks,
					  pUsrBlockList->pBlockEntry,
					  &pInterBuildBuff->buffMainH);
		if (rc != 0) {
			CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for dlli contig user buffer 0x%x\n", rc);
			rc = CC_RET_NOMEM;
			goto endError_dataPtrToDma;
		}
		// if case numOfBlocks returned bigger than 1, we declare error
		if (pUsrBlockList->numOfBlocks > SINGLE_BLOCK_ENTRY) {
			errorClearFlag  = UNMAP_FLAG_CONTIG_DLLI;
			CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for contig mem numOfBlocks > 1\n");
			rc = CC_RET_OSFAULT;
			goto endError_dataPtrToDma;
		}
		SET_DMA_WITH_DLLI(pDmaBuff, pUsrBlockList->pBlockEntry[0].blockPhysAddr, usrBuffSize);
		return 0;
	}


	// in case buffer is not contiguous:
	// if buffer size smaller than  DLLI_MAX_BUFF_SIZE:
	// 					copy user buffer to tailBuff to improve performance and build DLLI
	if (usrBuffSize < DLLI_MAX_BUFF_SIZE) {
		// copy userBuffer to tailBuffer
		if ((CC_PAL_DMA_DIR_TO_DEVICE == direction) ||
		    (CC_PAL_DMA_DIR_BI_DIRECTION == direction)) {
			CC_PalMemCopy(pTailBuff->pVirtBuffer, (uint8_t *)pUsrBuffer, usrBuffSize);
		}
		// map tailBuff to get physical address and lock+invalidate
		pUsrBlockList->numOfBlocks = SINGLE_BLOCK_ENTRY;
		rc = CC_PalDmaBufferMap((uint8_t *)pTailBuff->pVirtBuffer,
					  usrBuffSize,
					  direction,
					  &pUsrBlockList->numOfBlocks,
					  pUsrBlockList->pBlockEntry,
					  &pInterBuildBuff->buffTailH);
		if (rc != 0) {
			CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for dlli tail user buffer 0x%x\n", rc);
			rc = CC_RET_NOMEM;
			goto endError_dataPtrToDma;
		}
		// if case numOfBlocks returned bigger than 1, we declare error
		if (pUsrBlockList->numOfBlocks > SINGLE_BLOCK_ENTRY) {
			CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for dlli tail numOfBlocks > 1\n");
			errorClearFlag  = UNMAP_FLAG_SMALL_SIZE_DLLI;
			rc = CC_RET_OSFAULT;
			goto endError_dataPtrToDma;
		}
		SET_DMA_WITH_DLLI(pDmaBuff, pUsrBlockList->pBlockEntry[0].blockPhysAddr, usrBuffSize);
		return 0;
	}

	// otherwise (buffer size is not smaller than  DLLI_MAX_BUFF_SIZE) build MLLI:
	// 	first seperate tail from user buffer,
	if ((CC_PAL_DMA_DIR_TO_DEVICE == direction) ||
	    (CC_PAL_DMA_DIR_BI_DIRECTION == direction)) {
		CC_PalMemCopy(pTailBuff->pVirtBuffer, (uint8_t *)&pUsrBuffer[usrBuffSize-MIN_CRYPTO_TAIL_SIZE], MIN_CRYPTO_TAIL_SIZE);
	}
	// map the buffer except the last MIN_CRYPTO_TAIL_SIZE bytes
	pUsrBlockList->numOfBlocks = FW_MLLI_TABLE_LEN - 1;
	rc = CC_PalDmaBufferMap((uint8_t *)pUsrBuffer,
				  (usrBuffSize-MIN_CRYPTO_TAIL_SIZE),
				  direction,
				  &pUsrBlockList->numOfBlocks,
				  pUsrBlockList->pBlockEntry,
				  &pInterBuildBuff->buffMainH);
	if (rc != 0) {
		CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for mlli user buffer 0x%x\n", rc);
		rc = CC_RET_NOMEM;
		goto endError_dataPtrToDma;
	}
	// if case numOfBlocks returned bigger than (FW_MLLI_TABLE_LEN-1), we declare error since we have no room for
	// first dummy entry in MLLI and the last entry for tail
	if (pUsrBlockList->numOfBlocks > (FW_MLLI_TABLE_LEN-1)) {
		CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for mlli numOfBlocks > (FW_MLLI_TABLE_LEN-1)\n");
		errorClearFlag  = UNMAP_FLAG_MLLI_MAIN;
		rc = CC_RET_OSFAULT;
		goto endError_dataPtrToDma;
	}
	// map the tail
	numOfBlocks = SINGLE_BLOCK_ENTRY;
	rc = CC_PalDmaBufferMap((uint8_t *)pTailBuff->pVirtBuffer,
				  MIN_CRYPTO_TAIL_SIZE,
				  direction,
				  &numOfBlocks,
				  &pUsrBlockList->pBlockEntry[pUsrBlockList->numOfBlocks],
				  &pInterBuildBuff->buffTailH);
	if (rc != 0) {
		errorClearFlag  = (UNMAP_FLAG_MLLI_MAIN);
		CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for mllitail 0x%x\n", rc);
		rc = CC_RET_NOMEM;
		goto endError_dataPtrToDma;
	}
	// if case numOfBlocks returned bigger than 1, we declare error
	if (numOfBlocks > SINGLE_BLOCK_ENTRY) {
		CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for mlli numOfBlocks > 1\n");
		errorClearFlag  = (UNMAP_FLAG_MLLI_MAIN | UNMAP_FLAG_MLLI_TAIL);
		rc = CC_RET_OSFAULT;
		goto endError_dataPtrToDma;
	}

	// build MLLI
	buildMlliTable(pDevBuffer, pUsrBlockList);

	// map MLLI
	numOfBlocks = SINGLE_BLOCK_ENTRY;
	rc = CC_PalDmaBufferMap((uint8_t *)pDevBuffer->pLliEntry,
				  (pUsrBlockList->numOfBlocks+2)*sizeof(lliInfo_t),
				  CC_PAL_DMA_DIR_BI_DIRECTION,
				  &numOfBlocks,
				  &pDevBuffer->mlliBlockInfo,
				  &pInterBuildBuff->buffMlliH);
	if (rc != 0) {
		CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for mlli table 0x%x\n", rc);
		errorClearFlag  = (UNMAP_FLAG_MLLI_MAIN | UNMAP_FLAG_MLLI_TAIL );
		rc = CC_RET_NOMEM;
		goto endError_dataPtrToDma;
	}
	// if case numOfBlocks returned bigger than 1, we declare error
	if (numOfBlocks > SINGLE_BLOCK_ENTRY) {
		CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for mlli numOfBlocks > 1\n");
		errorClearFlag  = (UNMAP_FLAG_MLLI_MAIN | UNMAP_FLAG_MLLI_TAIL | UNMAP_FLAG_MLLI_TABLE);
		rc = CC_RET_OSFAULT;
		goto endError_dataPtrToDma;
	}
	SET_DMA_WITH_MLLI(pDmaBuff, pDevBuffer->mlliBlockInfo.blockPhysAddr, pDevBuffer->mlliBlockInfo.blockSize);
	return 0;

endError_dataPtrToDma:
	if (UNMAP_FLAG_CONTIG_DLLI & errorClearFlag) {
		CC_PalDmaBufferUnmap((uint8_t *)pUsrBuffer,
					  usrBuffSize,
					  direction,
					  pUsrBlockList->numOfBlocks,
					  pUsrBlockList->pBlockEntry,
					  pInterBuildBuff->buffMainH);
	}
	if (UNMAP_FLAG_SMALL_SIZE_DLLI & errorClearFlag) {
		CC_PalDmaBufferUnmap((uint8_t *)pTailBuff->pVirtBuffer,
					  usrBuffSize,
					  direction,
					  pUsrBlockList->numOfBlocks,
					  pUsrBlockList->pBlockEntry,
					  pInterBuildBuff->buffTailH);
	}
	if (UNMAP_FLAG_MLLI_MAIN & errorClearFlag) {
		CC_PalDmaBufferUnmap((uint8_t *)pUsrBuffer,
					  (usrBuffSize-MIN_CRYPTO_TAIL_SIZE),
					  direction,
					  pUsrBlockList->numOfBlocks,
					  pUsrBlockList->pBlockEntry,
					  pInterBuildBuff->buffMainH);
	}
	if (UNMAP_FLAG_MLLI_TAIL & errorClearFlag) {
		CC_PalDmaBufferUnmap((uint8_t *)pTailBuff->pVirtBuffer,
				       MIN_CRYPTO_TAIL_SIZE,
				       direction,
				       SINGLE_BLOCK_ENTRY,
				       &pUsrBlockList->pBlockEntry[pUsrBlockList->numOfBlocks],
				       pInterBuildBuff->buffTailH);
	}
	if (UNMAP_FLAG_MLLI_TABLE & errorClearFlag) {
		CC_PalDmaBufferUnmap((uint8_t *)pDevBuffer->pLliEntry,
				      (pUsrBlockList->numOfBlocks+2)*sizeof(lliInfo_t),
				      CC_PAL_DMA_DIR_BI_DIRECTION,
				      SINGLE_BLOCK_ENTRY,
				      &pDevBuffer->mlliBlockInfo,
				      pInterBuildBuff->buffMlliH);
	}
	return rc;

}


/**
 * @brief   sets user buffer into dma buffer to be used by HW
 *
 *
 * @param[in] pUsrBuffer - address of the buffer allocated by user
 * @param[in] usrBuffSize - data direction: into device, from device or bidirectional
 * @param[in] direction - bi-directional/to/from device
 * @param[in] pDmaBuff - dma buffer to be used by HW
 * @param[in] pInterBuildBuff - mlli list,  page list abd cookies used to build the dms bufffer
 *
 * @return success/fail
 */
static uint32_t buildDataPtrFromDma(uint8_t 		*pUsrBuffer,
		                    size_t 		usrBuffSize,
		                    CCPalDmaBufferDirection_t direction,
		                    DmaBuffer_s 	*pDmaBuff,
		                    interDmaBuildBuffer_t *pInterBuildBuff)
{
	uint32_t		rc = 0;
	tailBuffInfo_t		*pTailBuff = NULL;
	mlliTable_t 		*pDevBuffer = NULL;
	dmaBuffBlocksInfo_t   	*pUsrBlockList = NULL;

	pDmaBuff = pDmaBuff;
	/// check inputs
	if (NULL == pInterBuildBuff) {
		CC_PAL_LOG_ERR("invalid parameters\n");
		return CC_RET_INVARG;
	}
        // first check if buffer is NULL, build simple empty dma buffer
	if ((NULL == pUsrBuffer) ||
	    (0 == usrBuffSize)) {
		return 0;
	}

	pDevBuffer = &pInterBuildBuff->devBuffer;
	pUsrBlockList = &pInterBuildBuff->blocksList;
	pTailBuff = &pInterBuildBuff->tailBuff;

	// second case, if buffer is contiguous build DLLI
	if (CC_PalIsDmaBufferContiguous(pUsrBuffer, usrBuffSize)) {
		rc = CC_PalDmaBufferUnmap((uint8_t *)pUsrBuffer,
				       usrBuffSize,
				       direction,
				       pUsrBlockList->numOfBlocks,
				       pUsrBlockList->pBlockEntry,
				       pInterBuildBuff->buffMainH);
		goto endError_dmaToDataPtr;
	}


	// in case buffer is not contiguous:
	// if buffer size smaller than  DLLI_MAX_BUFF_SIZE:
	// 					copy user buffer to tailBuff to improve performance and build DLLI
	if (usrBuffSize < DLLI_MAX_BUFF_SIZE) {
		// map tailBuff to get physical address and lock+invalidate
		rc = CC_PalDmaBufferUnmap((uint8_t *)pTailBuff->pVirtBuffer,
				       usrBuffSize,
				       direction,
				       pUsrBlockList->numOfBlocks,
				       pUsrBlockList->pBlockEntry,
				       pInterBuildBuff->buffTailH);
		// copy userBuffer to tailBuffer
		if ((CC_PAL_DMA_DIR_FROM_DEVICE == direction) ||
		    (CC_PAL_DMA_DIR_BI_DIRECTION == direction)) {
			CC_PalMemCopy((uint8_t *)pUsrBuffer, pTailBuff->pVirtBuffer, usrBuffSize);
		}
		goto endError_dmaToDataPtr;
	}

	// otherwise (buffer size smaller than  DLLI_MAX_BUFF_SIZE) build MLLI:
	// 					first seperate tail from user buffer,
	// unmap the buffer except the last MIN_CRYPTO_TAIL_SIZE bytes
	rc = CC_PalDmaBufferUnmap((uint8_t *)pUsrBuffer,
			       (usrBuffSize-MIN_CRYPTO_TAIL_SIZE),
			       direction,
			       pUsrBlockList->numOfBlocks,
			       pUsrBlockList->pBlockEntry,
			       pInterBuildBuff->buffMainH);
	// Unmap the tail
	rc |= CC_PalDmaBufferUnmap((uint8_t *)pTailBuff->pVirtBuffer,
			      MIN_CRYPTO_TAIL_SIZE,
			      direction,
			      SINGLE_BLOCK_ENTRY,
			      &pUsrBlockList->pBlockEntry[pUsrBlockList->numOfBlocks],
			      pInterBuildBuff->buffTailH);
	if ((CC_PAL_DMA_DIR_FROM_DEVICE == direction) ||
	    (CC_PAL_DMA_DIR_BI_DIRECTION == direction)) {
		CC_PalMemCopy((uint8_t *)&pUsrBuffer[usrBuffSize-MIN_CRYPTO_TAIL_SIZE], pTailBuff->pVirtBuffer, MIN_CRYPTO_TAIL_SIZE);
	}

	// Unmap MLLI
	rc |= CC_PalDmaBufferUnmap((uint8_t *)pDevBuffer->pLliEntry,
			       (pUsrBlockList->numOfBlocks+2)*sizeof(lliInfo_t),
			       CC_PAL_DMA_DIR_BI_DIRECTION,
			       SINGLE_BLOCK_ENTRY,
			       &pDevBuffer->mlliBlockInfo,
			       pInterBuildBuff->buffMlliH);

endError_dmaToDataPtr:
	if (rc != 0) {
		rc = CC_RET_BUSY;
	}
	return rc;

}

static void isCopyCtxRequired(enum drv_crypto_alg alg, int mode, uint8_t *flag)
{
	*flag=0;

	switch(alg)
	{
		case DRV_CRYPTO_ALG_AES:
			if (mode == DRV_CIPHER_XCBC_MAC) {
				*flag = 1;
			}
			break;
		case DRV_CRYPTO_ALG_AEAD:
        case DRV_CRYPTO_ALG_DES:
        case DRV_CRYPTO_ALG_HMAC:
        case DRV_CRYPTO_ALG_HASH:
            *flag = 1;
			break;
		case DRV_CRYPTO_ALG_BYPASS:
			break;
		default:
			break;
	}
}

/******************************************************************************
*				PUBLIC FUNCTIONS
******************************************************************************/

/*!
 * Allocate sym adaptor driver resources
 *
 * \param None
 *
 * \return 0 for success, otherwise failure
 */
int SymDriverAdaptorModuleInit()
{
	int symRc = CC_RET_OK;

	symRc = allocDmaBuildBuffers(&g_dmaInBuildBuffH);
	if (symRc != CC_RET_OK) {
		return CC_RET_NOMEM;
	}

	symRc = allocDmaBuildBuffers(&g_dmaOutBuildBuffH);
	if (symRc != CC_RET_OK) {
		freeDmaBuildBuffers(&g_dmaInBuildBuffH);
		return CC_RET_NOMEM;
	}

	symRc = AllocCompletionPlatBuffer();
	if (symRc != CC_RET_OK) {
		freeDmaBuildBuffers(&g_dmaInBuildBuffH);
		freeDmaBuildBuffers(&g_dmaOutBuildBuffH);
		return CC_RET_NOMEM;
	}

	return CC_RET_OK;
}


/*!
 * Release sym adaptor driver resources
 *
 * \param None
 *
 * \return always success
 */
int SymDriverAdaptorModuleTerminate()
{
	freeDmaBuildBuffers(&g_dmaInBuildBuffH);
	freeDmaBuildBuffers(&g_dmaOutBuildBuffH);
	FreeCompletionPlatBuffer();

	return CC_RET_OK;
}

static uint32_t symDriverAdaptorCopySramBuff(enum dx_driver_adaptor_dir dir, CCSramAddr_t sram_addr, uint32_t *buff, uint32_t size)
{
	DmaBuffer_s dmaBuffIn, dmaBuffOut;
	CC_PalDmaBufferHandle dmaHandle;
	CCPalDmaBlockInfo_t	dmaBlockEntry;
	uint32_t numOfBlocks;
	uint32_t rc,symRc;
	numOfBlocks = SINGLE_BLOCK_ENTRY;

	rc = CC_PalDmaBufferMap((uint8_t *)buff,
				  size,
				  CC_PAL_DMA_DIR_BI_DIRECTION,
				  &numOfBlocks,
				  &dmaBlockEntry,
				  &dmaHandle);
	if (rc != 0) {
		CC_PAL_LOG_ERR("failed to CC_PalDmaBufferMap for contig user context  0x%x\n", rc);
		return CC_RET_NOMEM;
	}

	if(dir == dx_driver_adaptor_in) {
		SET_DMA_WITH_DLLI(((DmaBuffer_s*)&dmaBuffIn), dmaBlockEntry.blockPhysAddr, size);

		dmaBuffOut.size = size;
		dmaBuffOut.pData = sram_addr;
		dmaBuffOut.dmaBufType = DMA_BUF_SEP;
		dmaBuffOut.axiNs = 0;
	}else {
		SET_DMA_WITH_DLLI(((DmaBuffer_s*)&dmaBuffOut), dmaBlockEntry.blockPhysAddr, size);

		dmaBuffIn.size = size;
		dmaBuffIn.pData = sram_addr;
		dmaBuffIn.dmaBufType = DMA_BUF_SEP;
		dmaBuffIn.axiNs = 0;

	}
	/* Write BYPASS without use of context. the ALG of bypass is now passed as a parameter to the
	dispatch process. the context adress is not used by processBypass  */
	symRc = SymDriverDispatchProcess(0, buff, &dmaBuffIn, &dmaBuffOut, DRV_CRYPTO_ALG_BYPASS);
	if (symRc != CC_RET_OK) {
		goto EndWithErr;
	}
	WaitForSequenceCompletion();

EndWithErr:
	rc = CC_PalDmaBufferUnmap((uint8_t *)buff,
				  size,
				  CC_PAL_DMA_DIR_BI_DIRECTION,
				  numOfBlocks,
				  &dmaBlockEntry,
				  dmaHandle);
	if(symRc) {
		return symRc;
	}

	return rc;
}

uint32_t symDriverAdaptorCopyCtx(enum dx_driver_adaptor_dir dir, CCSramAddr_t sram_address, uint32_t *pCtx, enum drv_crypto_alg alg)
{
	uint32_t rc = 0;
	switch (dir) {
		case dx_driver_adaptor_in:
			rc = symDriverAdaptorCopySramBuff(dx_driver_adaptor_in, sram_address, (uint32_t*)pCtx, SymDriverAdaptorGetCtxSize(alg));
			break;

		case dx_driver_adaptor_out:
			rc = symDriverAdaptorCopySramBuff(dx_driver_adaptor_out, sram_address, (uint32_t*)pCtx, SymDriverAdaptorGetCtxSize(alg));
			break;

	default:
			rc = CC_RET_INVARG;
			break;
	}

	return rc;
}

/*!
 * Initializes the caller context by invoking the symmetric dispatcher driver.
 * The caller context may resides in SRAM or DCACHE SEP areas.
 * This function flow is synchronouse.
 *
 * \param pCtx
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int SymDriverAdaptorInit(uint32_t *pCtx, enum drv_crypto_alg alg, int mode)
{
	int symRc = CC_RET_OK;
	CCPalPerfData_t perfIdx = 0;
	uint8_t isCpyCtxFlag=0;

	CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_INIT);
	CC_PAL_LOG_INFO("pCtx=%p\n", pCtx);
	if (pCtx == NULL) {
		CC_PAL_LOG_ERR("NULL pointer was given for ctx\n");
		return CC_RET_INVARG_CTX;
	}
	symRc = CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE);
	if (symRc != CC_SUCCESS) {
		CC_PalAbort("Fail to acquire mutex\n");
	}
	isCopyCtxRequired(alg, mode, &isCpyCtxFlag);
	if (isCpyCtxFlag) {
		symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_in, CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx, alg);
		if (symRc != CC_RET_OK) {
			goto EndWithErr;
		}
    }
	/* call the dispatcher with the new context pointer in SRAM */
	symRc = SymDriverDispatchInit(CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx, alg);
	if (symRc != CC_RET_OK) {
		goto EndWithErr;
	}
	WaitForSequenceCompletion();

	if (isCpyCtxFlag) {
		symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_out, CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx, alg);
	}
	CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_INIT);
EndWithErr:
	if(CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_SUCCESS) {
		CC_PalAbort("Fail to release mutex\n");
	}
	return symRc;
}

/*!
 * Process a cryptographic data by invoking the symmetric dispatcher driver.
 * The invoker may request any amount of data aligned to the given algorithm
 * block size. It uses a scratch pad to copy (in cpu mode) the user
 * data from DCACHE/ICACHE to SRAM for processing. This function flow is
 * synchronouse.
 *
 * \param pCtx may resides in SRAM or DCACHE SeP areas
 * \param pDataIn The input data buffer. It may reside in SRAM, DCACHE or ICACHE SeP address range
 * \param pDataOut The output data buffer. It may reside in SRAM or DCACHE SeP address range
 * \param DataSize The data input size in octets
 * \param alg The algorithm of the operation.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int SymDriverAdaptorProcess(uint32_t* pCtx,
				void* pDataIn, void* pDataOut, size_t DataSize, enum drv_crypto_alg alg)
{
	int 			symRc = CC_RET_OK;
	DmaBuffer_s 		dmaBuffIn;
	DmaBuffer_s		dmaBuffOut;
	uint32_t                retCode;
	struct drv_ctx_cipher 	*pAesContext = (struct drv_ctx_cipher *)pCtx;
	uint32_t		dmaBuiltFlag = DMA_BUILT_FLAG_NONE;
	CCPalPerfData_t       perfIdx = 0;

	CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_PROC);
	CC_PAL_LOG_INFO("pCtx=%p\n", pCtx);
	CC_PAL_LOG_INFO("IN addr=%p OUT addr=%p DataSize=%u\n", pDataIn, pDataOut, DataSize);


	if ((pCtx == NULL) || (pDataIn == NULL)) {
		CC_PAL_LOG_ERR("NULL pointer was given for ctx or din\n");
		return CC_RET_INVARG_CTX;
	}

	/* In AES mac modes there is no output so it needs special treatment */
	if ((alg == DRV_CRYPTO_ALG_AES) &&
	    ((pAesContext->mode == DRV_CIPHER_CBC_MAC) ||
	     (pAesContext->mode == DRV_CIPHER_XCBC_MAC) ||
	     (pAesContext->mode == DRV_CIPHER_CMAC))) {
		/* clear the output to mark that it is not used */
		pDataOut = NULL;
	}

	retCode = CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE);
	if (retCode != CC_SUCCESS) {
		CC_PalAbort("Fail to acquire mutex\n");
	}

	// in case of inplace - map only one buffer bi directional
	if (pDataIn == pDataOut) {
		retCode = buildDmaFromDataPtr((uint8_t *)pDataIn, DataSize, CC_PAL_DMA_DIR_BI_DIRECTION,
						&dmaBuffIn, &g_dmaInBuildBuffH);
		if (retCode != 0) {
			symRc = retCode;
			CC_PAL_LOG_ERR("failed to buildDmaFromDataPtr for pDataIn inplace 0x%x\n", retCode);
			goto processUnlockMutex;
		}
		dmaBuiltFlag = DMA_BUILT_FLAG_BI_DIR;
		COPY_DMA_BUFF(dmaBuffOut, dmaBuffIn);
	}else {
		retCode = buildDmaFromDataPtr((uint8_t *)pDataIn, DataSize, CC_PAL_DMA_DIR_TO_DEVICE,
						&dmaBuffIn, &g_dmaInBuildBuffH);
		if (retCode != 0) {
			symRc = retCode;
			CC_PAL_LOG_ERR("failed to buildDmaFromDataPtr for pDataIn 0x%x\n", retCode);
			goto processUnlockMutex;
		}
		dmaBuiltFlag = DMA_BUILT_FLAG_INPUT_BUFF;
		retCode = buildDmaFromDataPtr((uint8_t *)pDataOut, DataSize, CC_PAL_DMA_DIR_FROM_DEVICE,
						&dmaBuffOut, &g_dmaOutBuildBuffH);
		if (retCode != 0) {
			CC_PAL_LOG_ERR("failed to buildDmaFromDataPtr for pDataOut 0x%x\n", retCode);
			symRc = retCode;
			goto EndWithErr;
		}
		dmaBuiltFlag |= DMA_BUILT_FLAG_OUTPUT_BUFF;
	}

	symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_in, CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx, alg);
	if (symRc != CC_RET_OK) {
		goto EndWithErr;
	}

	symRc = SymDriverDispatchProcess(CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx, &dmaBuffIn, &dmaBuffOut, alg);
	if (symRc != CC_RET_OK) {
		goto EndWithErr;
	}

	WaitForSequenceCompletion();
	symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_out, CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx, alg);
EndWithErr:
	// in case of inplace - unmap only one buffer bi directional
	if (dmaBuiltFlag & DMA_BUILT_FLAG_BI_DIR) {
		retCode = buildDataPtrFromDma((uint8_t *)pDataIn, DataSize, CC_PAL_DMA_DIR_BI_DIRECTION,
						&dmaBuffIn, &g_dmaInBuildBuffH);
		if (retCode != 0) {
			CC_PAL_LOG_ERR("failed to buildDataPtrFromDma for pDataIn inplace 0x%x\n", retCode);
			symRc = retCode;
		}
	}
	if (dmaBuiltFlag & DMA_BUILT_FLAG_INPUT_BUFF) {
		retCode = buildDataPtrFromDma((uint8_t *)pDataIn, DataSize, CC_PAL_DMA_DIR_TO_DEVICE,
						&dmaBuffIn, &g_dmaInBuildBuffH);
		if (retCode != 0) {
			CC_PAL_LOG_ERR("failed to buildDataPtrFromDma for pDataIn 0x%x\n", retCode);
			symRc = retCode;
		}
	}
	if (dmaBuiltFlag & DMA_BUILT_FLAG_OUTPUT_BUFF) {
		retCode = buildDataPtrFromDma((uint8_t *)pDataOut, DataSize, CC_PAL_DMA_DIR_FROM_DEVICE,
						&dmaBuffOut, &g_dmaOutBuildBuffH);
		if (retCode != 0) {
			CC_PAL_LOG_ERR("failed to buildDataPtrFromDma for pDataOut 0x%x\n", retCode);
			symRc = retCode;
		}
	}

	CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_PROC);
processUnlockMutex:
	if(CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_SUCCESS) {
		CC_PalAbort("Fail to release mutex\n");
	}
	return symRc;
}

/*!
 * Finalizing the cryptographic data by invoking the symmetric dispatcher driver.
 * It calls the `SymDriverDcacheAdaptorFinalize` function for processing by leaving
 * any reminder for the finalize operation.
 *
 * \param pCtx may resides in SRAM or DCACHE SeP areas
 * \param pDataIn The input data buffer. It may reside in SRAM, DCACHE or ICACHE SeP address range
 * \param pDataOut The output data buffer. It may reside in SRAM or DCACHE SeP address range
 * \param DataSize The data input size in octets
 * \param alg The algorithm of the operation.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int SymDriverAdaptorFinalize(uint32_t* pCtx,
				void* pDataIn, void* pDataOut, size_t DataSize, enum drv_crypto_alg alg)
{
	DmaBuffer_s dmaBuffIn, dmaBuffOut;
	int symRc = CC_RET_OK;
	struct drv_ctx_cipher *pAesContext = (struct drv_ctx_cipher *)pCtx;
	uint32_t                retCode;
	/* used to differ AES MAC modes (where the dout is not NULL, but is not access via DMA */
	uint32_t isMac = CC_FALSE;
	void 		*pTmpDataOut = pDataOut;
	uint32_t	dmaBuiltFlag = DMA_BUILT_FLAG_NONE;
	CCPalPerfData_t  perfIdx = 0;

	CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_FIN);

	CC_PAL_LOG_INFO("pCtx=%p\n", pCtx);
	CC_PAL_LOG_INFO("IN addr=%p OUT addr=%p DataSize=%u\n", pDataIn, pDataOut, DataSize);

	/* do not check din pointer since hash/hmac algs has no data input */
	if (pCtx == NULL) {
		CC_PAL_LOG_ERR("NULL pointer was given for ctx\n");
		return CC_RET_INVARG_CTX;
	}
	if ((alg == DRV_CRYPTO_ALG_AES) &&
	    ((pAesContext->mode == DRV_CIPHER_CBC_MAC) ||
	     (pAesContext->mode == DRV_CIPHER_XCBC_MAC) ||
	     (pAesContext->mode == DRV_CIPHER_CMAC))){
		isMac = CC_TRUE;
		pTmpDataOut = NULL;
	}

	retCode = CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE);
	if (retCode != CC_SUCCESS) {
		CC_PalAbort("Fail to acquire mutex\n");
	}

	// in case of inplace - map only one buffer bi directional
	if ((pDataIn == pDataOut) && !isMac) {
		retCode = buildDmaFromDataPtr((uint8_t *)pDataIn, DataSize, CC_PAL_DMA_DIR_BI_DIRECTION,
						&dmaBuffIn, &g_dmaInBuildBuffH);
		if (retCode != 0) {
			CC_PAL_LOG_ERR("failed to buildDmaFromDataPtr for pDataIn inplace 0x%x\n", retCode);
			symRc = retCode;
			goto finalizeUnlockMutex;
		}
		dmaBuiltFlag = DMA_BUILT_FLAG_BI_DIR;
		COPY_DMA_BUFF(dmaBuffOut, dmaBuffIn);
	}else {
		retCode = buildDmaFromDataPtr((uint8_t *)pDataIn, DataSize, CC_PAL_DMA_DIR_TO_DEVICE,
						&dmaBuffIn, &g_dmaInBuildBuffH);
		if (retCode != 0) {
			CC_PAL_LOG_ERR("failed to buildDmaFromDataPtr for pDataIn 0x%x\n", retCode);
			symRc = retCode;
			goto finalizeUnlockMutex;
		}
		dmaBuiltFlag = DMA_BUILT_FLAG_INPUT_BUFF;
		retCode = buildDmaFromDataPtr((uint8_t *)pTmpDataOut, DataSize, CC_PAL_DMA_DIR_FROM_DEVICE,
						&dmaBuffOut, &g_dmaOutBuildBuffH);
		if (retCode != 0) {
			CC_PAL_LOG_ERR("failed to buildDmaFromDataPtr for pDataOut 0x%x\n", retCode);
			symRc = retCode;
			goto EndWithErr;
		}
		dmaBuiltFlag |= DMA_BUILT_FLAG_OUTPUT_BUFF;
	}

	symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_in, CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx, alg);
	if (symRc != CC_RET_OK) {
		goto EndWithErr;
	}

	symRc = SymDriverDispatchFinalize(CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx, &dmaBuffIn, &dmaBuffOut, alg);
	if (symRc != CC_RET_OK) {
		goto EndWithErr;
	}

	WaitForSequenceCompletion();

	symRc = symDriverAdaptorCopyCtx(dx_driver_adaptor_out, CC_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR, pCtx, alg);

EndWithErr:
	// in case of inplace - unmap only one buffer bi directional
	if (dmaBuiltFlag & DMA_BUILT_FLAG_BI_DIR) {
		retCode = buildDataPtrFromDma((uint8_t *)pDataIn, DataSize, CC_PAL_DMA_DIR_BI_DIRECTION,
						&dmaBuffIn, &g_dmaInBuildBuffH);
		if (retCode != 0) {
			CC_PAL_LOG_ERR("failed to buildDataPtrFromDma for pDataIn inplace 0x%x\n", retCode);
			symRc = retCode;
		}
	}
	if  (dmaBuiltFlag & DMA_BUILT_FLAG_INPUT_BUFF) {
		retCode = buildDataPtrFromDma((uint8_t *)pDataIn, DataSize, CC_PAL_DMA_DIR_TO_DEVICE,
						&dmaBuffIn, &g_dmaInBuildBuffH);
		if (retCode != 0) {
			CC_PAL_LOG_ERR("failed to buildDataPtrFromDma for pDataIn 0x%x\n", retCode);
			symRc = retCode;
		}
	}
	if  (dmaBuiltFlag & DMA_BUILT_FLAG_OUTPUT_BUFF) {
		retCode = buildDataPtrFromDma((uint8_t *)pTmpDataOut, DataSize, CC_PAL_DMA_DIR_FROM_DEVICE,
						&dmaBuffOut, &g_dmaOutBuildBuffH);
		if (retCode != 0) {
			CC_PAL_LOG_ERR("failed to buildDataPtrFromDma for pDataOut 0x%x\n", retCode);
			symRc = retCode;
		}
	}

	if(isMac == CC_TRUE) {
		switch(pAesContext->mode) {
			case DRV_CIPHER_CBC_MAC:
			case DRV_CIPHER_XCBC_MAC:
			case DRV_CIPHER_CMAC:
				if (pDataOut == NULL){ /* in case of MAC the data out must not be NULL (MAC is copied to it) */
					symRc = CC_RET_INVARG;
					goto finalizeUnlockMutex;
				}
				CC_PalMemCopy(pDataOut,pAesContext->block_state,CC_AES_BLOCK_SIZE);
			default:
				break;
		}
	}

	CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SYM_DRV_FIN);
finalizeUnlockMutex:
	if(CC_PalMutexUnlock(&CCSymCryptoMutex) != CC_SUCCESS) {
		CC_PalAbort("Fail to release mutex\n");
	}
	return symRc;
}


