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



/************* Include Files ****************/
#include "cc_pal_log.h"
#include "cc_plat.h"
#include "cc_pal_dma.h"
#include "cc_pal_memmap.h"
#include "cc_pal_perf.h"
#include "cc_general_defs.h"
#include <string.h>

CCDmaAddr_t gMemBaseAddr = 0;
static uint32_t gMemNextAddr = 0;


#define PAL_MAX_COOKIES_NUM	260  // 2*FW_MLLI_TABLE_LEN + 10 reserved
#define PAL_MAX_MAP_HANDLE   10   // in case of MLLI we need 3 for inBuff, 3 for outBuff and 4 reserved

#define PAL_PAGE_SHIFT 12
#define PAL_PAGE_SIZE (1 << PAL_PAGE_SHIFT)
#define PAL_PAGE_MASK (~(PAL_PAGE_SIZE-1))

#define PAL_FALSE 0
#define PAL_TRUE 1

typedef struct {
	uint32_t	      buffSize;
	uint8_t               *pVirtBuffAddr;
	uint8_t	      	      isTaken;
}PalIntDmaMapCookies_t;

typedef struct {
	uint32_t			index;
	uint8_t	      	   		isUsed;
	uint32_t      	   		numOfTakenCookies;
	PalIntDmaMapCookies_t  	cookeis[PAL_MAX_COOKIES_NUM];
}PalIntDmaMapHandle_t;


static PalIntDmaMapHandle_t cookiesDB[PAL_MAX_MAP_HANDLE];


static uint32_t PalCalcPageSize(uint32_t index,
			            uint32_t numPages,
			            uint8_t * pDataBuffer,
			            uint32_t buffSize,
			            uint32_t startOffset)
{
	uint32_t size = 0;

	if (index == 0) {
		if ((PAL_PAGE_SIZE - startOffset) >= buffSize) {
			return buffSize;
		}
		return (PAL_PAGE_SIZE - startOffset);
	}

	if (index == (numPages -1)) {
		size = ((uint32_t)(pDataBuffer + buffSize)) & (~PAL_PAGE_MASK);
		if(size == 0x0){
			size = PAL_PAGE_SIZE;
		}
		return size;
	}

	return PAL_PAGE_SIZE;
}


static PalIntDmaMapHandle_t * PalGetDmaHandle(uint32_t *handle)
{
	uint32_t i;
	for (i=0; i<PAL_MAX_MAP_HANDLE;i++ ) {
		if(cookiesDB[i].isUsed == PAL_FALSE) {
			cookiesDB[i].isUsed = PAL_TRUE;
			*handle = i;
			return &cookiesDB[i];
		}
	}
	return NULL;
}

static  void PalFreeDmaHandle(uint32_t handle)
{
	if (handle >= PAL_MAX_MAP_HANDLE) {
		return;
	}
	memset((uint8_t *)&cookiesDB[handle].cookeis, 0, sizeof(cookiesDB[handle].cookeis));
	cookiesDB[handle].isUsed = PAL_FALSE;
}

static PalIntDmaMapCookies_t * PalGetCookie(uint32_t handle, uint32_t *cookieIdx)
{
	uint32_t i;

	if (handle >= PAL_MAX_MAP_HANDLE) {
		return NULL;
	}
	if (cookiesDB[handle].numOfTakenCookies >= PAL_MAX_COOKIES_NUM) {
		return NULL;
	}
	for (i=0; i<PAL_MAX_COOKIES_NUM;i++ ) {
		if(cookiesDB[handle].cookeis[i].isTaken == PAL_FALSE) {
			cookiesDB[handle].cookeis[i].isTaken = PAL_TRUE;
			cookiesDB[handle].numOfTakenCookies++;
			*cookieIdx = i;
			return &cookiesDB[handle].cookeis[i];
		}
	}
	return NULL;
}

static PalIntDmaMapCookies_t* PalGetCookieByIndex(uint32_t handle, uint32_t cookieIndex)
{
	if ((handle >= PAL_MAX_MAP_HANDLE) ||
	    (cookieIndex >= PAL_MAX_COOKIES_NUM)) {
		return NULL;
	}
	if(cookiesDB[handle].cookeis[cookieIndex].isTaken == PAL_FALSE) {
		return NULL;
	}
	return &cookiesDB[handle].cookeis[cookieIndex];
}


static uint32_t PalReleaseCookie(uint32_t handle, uint32_t cookieIndex)
{
	if ((handle >= PAL_MAX_MAP_HANDLE) ||
	    (cookieIndex >= PAL_MAX_COOKIES_NUM)) {
		return 1;
	}
	if(cookiesDB[handle].cookeis[cookieIndex].isTaken == PAL_FALSE) {
		return 2;
	}
	if (cookiesDB[handle].numOfTakenCookies < 1) {
		return 3;
	}
	cookiesDB[handle].cookeis[cookieIndex].buffSize = 0;
	cookiesDB[handle].cookeis[cookieIndex].pVirtBuffAddr = NULL;
	cookiesDB[handle].cookeis[cookieIndex].isTaken = PAL_FALSE;
	cookiesDB[handle].numOfTakenCookies--;
	return 0;
}


static void PalInitCookies(void)
{
	uint32_t i = 0;

	memset((uint8_t *)cookiesDB, 0, sizeof(cookiesDB));
	for (i = 0; i<PAL_MAX_MAP_HANDLE ; i++) {
		cookiesDB[i].index = i;
	}
}

/*******************************************************************************************************/
/******* Public functions                                                       ************************/
/*******************************************************************************************************/

/**
 * @brief  initialize cookies and memory used for dma operations
 *
 * @param[in] buffSize - buffer size in Bytes
 * @param[in] physBuffAddr - physical start address of the memory to map
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t CC_PalDmaInit(uint32_t  buffSize,
                        CCDmaAddr_t  physBuffAddr)
{
	CC_UNUSED_PARAM(buffSize);
	gMemBaseAddr = physBuffAddr;

	gMemNextAddr = gMemBaseAddr;
	PalInitCookies();
	return 0;
}

/**
 * @brief   free system resources created in PD_PAL_DmaInit()
 *
 * @param[in] buffSize - buffer size in Bytes
 *
 * @return void
 */
void CC_PalDmaTerminate(void)
{
	gMemBaseAddr = 0;
	gMemNextAddr = 0;
	return;
}


/**
 * @brief   Maps a given buffer of any type. Returns the list of DMA-able blocks that the buffer maps to.
 *
 * @param[in] pDataBuffer -  Address of the buffer to map
 * @param[in] buffSize - Buffer size in bytes
 * @param[in] copyDirection - Copy direction of the buffer. Can be TO_DEVICE, FROM_DEVICE or BI_DIRECTION
 * @param[in/out] numOfBlocks - maximum numOfBlocks to fill, as output the actual number
 * @param[out] pDmaBlockList - List of DMA-able blocks that the buffer maps to
 * @param[out] dmaBuffHandle - A handle to the mapped buffer private resources
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t CC_PalDmaBufferMap(uint8_t                	  *pDataBuffer,
			     uint32_t                     buffSize,
			     CCPalDmaBufferDirection_t  copyDirection,
			     uint32_t                     *pNumOfBlocks,
			     CCPalDmaBlockInfo_t        *pDmaBlockList,
			     CC_PalDmaBufferHandle       *dmaBuffHandle)
{
	uint32_t retCode = 0;
	uint32_t index = 0,rIndex=0;
	uint32_t cookie = 0;
	uint32_t dmaHandle = 0;
	PalIntDmaMapHandle_t *plDmaHandle = NULL;
	PalIntDmaMapCookies_t *plCookeis = NULL;
	uint32_t size = 0;
	uint32_t endPage = 0;
	uint32_t startPage = 0;
	uint32_t startOffset = 0;
	uint32_t numPages = 0;
	uint8_t  *pTmpBuff = pDataBuffer;
	CCPalPerfData_t perfIdx = 0;

	CC_UNUSED_PARAM(copyDirection);
	CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_PAL_MAP);


	if ((NULL == pNumOfBlocks) ||
	    (NULL == pDmaBlockList) ||
	    (NULL == dmaBuffHandle)) {
		retCode = 1;
		goto pal_mapEnd;
	}
	*(uint32_t*)dmaBuffHandle = 0;
	plDmaHandle = PalGetDmaHandle((uint32_t*)&dmaHandle);
	if(NULL == plDmaHandle){
		retCode = 2;
		goto pal_mapEnd;
	}

	// calculate number of blocks(pages) held by pDataBuffer
        endPage = (uint32_t)((pDataBuffer + buffSize) - 1) >> PAL_PAGE_SHIFT;
        startPage = ((uint32_t)pDataBuffer) >> PAL_PAGE_SHIFT;
        numPages = endPage - startPage + 1;
	if ((0 == numPages) || (numPages > *pNumOfBlocks)) {
		PalFreeDmaHandle(dmaHandle);
		retCode = 4;
		goto pal_mapEnd;
	}

	startOffset = (uint32_t)pDataBuffer & (~PAL_PAGE_MASK);
	*pNumOfBlocks = numPages;
	pTmpBuff = pDataBuffer;

	// fill rest of the pages in array
	for (index = 0; index < numPages; index++) {
		size = PalCalcPageSize(index, numPages, pDataBuffer, buffSize, startOffset);
		// get block's cookie
		plCookeis = PalGetCookie(dmaHandle, (uint32_t*)&cookie);
		if(plCookeis == NULL) {
			/* release all the allocated memories and cookies */
			for(rIndex = 0; rIndex < index ; rIndex++) {
				plCookeis = PalGetCookieByIndex(dmaHandle, rIndex);
				CC_PalDmaContigBufferFree(plCookeis->buffSize,
							   (plCookeis->pVirtBuffAddr));
				PalReleaseCookie(dmaHandle, rIndex);
			}
			PalFreeDmaHandle(dmaHandle);
			retCode = 5;
			goto pal_mapEnd;
		}
		plCookeis->buffSize = size;
		plCookeis->pVirtBuffAddr = pTmpBuff;

		pDmaBlockList[index].blockSize = plCookeis->buffSize;
		pDmaBlockList[index].blockPhysAddr = ((uint32_t)pTmpBuff);

		pTmpBuff += pDmaBlockList[index].blockSize;
	}

	*(uint32_t**)dmaBuffHandle = &plDmaHandle->index;

pal_mapEnd:
	CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_PAL_MAP);
	return retCode;
}

/**
 * @brief   Unmaps a given buffer, and frees its associated resources, if exist
 *
 * @param[in] pDataBuffer -  Address of the buffer to map
 * @param[in] buffSize - Buffer size in bytes
 * @param[in] copyDirection - Copy direction of the buffer. Can be TO_DEVICE, FROM_DEVICE or BI_DIRECTION
 * @param[in] numOfBlocks - Number of DMA-able blocks that the buffer maps to
 * @param[in] pDmaBlockList - List of DMA-able blocks that the buffer maps to
 * @param[in] dmaBuffHandle - A handle to the mapped buffer private resources
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t CC_PalDmaBufferUnmap(uint8_t                	    *pDataBuffer,
			       uint32_t                     buffSize,
			       CCPalDmaBufferDirection_t  copyDirection,
			       uint32_t                     numOfBlocks,
			       CCPalDmaBlockInfo_t        *pDmaBlockList,
			       CC_PalDmaBufferHandle       dmaBuffHandle)
{
	uint32_t retCode = 0;
	uint32_t index = 0;
	uint32_t dmaHandle = 0;
	PalIntDmaMapCookies_t *plCookeis = NULL;
	CCPalPerfData_t perfIdx = 0;

	CC_UNUSED_PARAM(pDataBuffer);
	CC_UNUSED_PARAM(buffSize);
	CC_UNUSED_PARAM(copyDirection);

	CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_PAL_UNMAP);

	if ((NULL == pDmaBlockList) ||
	    (NULL == dmaBuffHandle)) {
		retCode = 1;
		goto pal_unmapEnd;
	}
	dmaHandle = *(uint32_t*)dmaBuffHandle;
	if (dmaHandle > PAL_MAX_MAP_HANDLE) {
		retCode = 1;
		goto pal_unmapEnd;
	}
	// free resources
	for (index = 0; index < numOfBlocks; index++) {
		plCookeis = PalGetCookieByIndex(dmaHandle, index);
		if(plCookeis == NULL) {
			/* Although this is problem we can't stop as we must clear all cookies*/
			retCode = 2;
			continue;
		}

		// if buffer was not allocated/copy in CC_PalDmaBufferMap(), nothing left to be doen.Just return OK
		plCookeis->pVirtBuffAddr = NULL;
		plCookeis->buffSize = 0;
		PalReleaseCookie(dmaHandle, index);
	}
	/*After releasing all cookies we release the dmaHandle */
	PalFreeDmaHandle(dmaHandle);

pal_unmapEnd:
	CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_PAL_UNMAP);
	return retCode;
}



/**
 * @brief   Allocates a DMA-contiguous buffer, and returns both its physical and virtual addresses
 *
 *
 * @param[in] buffSize - Buffer size in bytes
 * @param[out] ppVirtBuffAddr - Virtual address of the allocated buffer
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t CC_PalDmaContigBufferAllocate(uint32_t          buffSize,
					uint8_t          **ppVirtBuffAddr)
{
	*ppVirtBuffAddr = (uint8_t *)gMemNextAddr;
	gMemNextAddr += ((buffSize+3)>>2)<<2;
	return 0;
}



/**
 * @brief   free resources previuosly allocated by CC_PalDmaContigBufferAllocate
 *
 *
 * @param[in] buffSize - buffer size in Bytes
 * @param[in] pVirtBuffAddr - virtual address of the buffer to free
 *
 * @return success/fail
 */
uint32_t CC_PalDmaContigBufferFree(uint32_t          buffSize,
				    uint8_t          *pVirtBuffAddr)
{
	CC_UNUSED_PARAM(buffSize);
	CC_UNUSED_PARAM(pVirtBuffAddr);
	return 0;
}



/**
 * @brief   release and free previously allocated buffers
 *
 * @param[in] pDataBuffer - User buffer address
 * @param[in] buffSize - User buffer size
 *
 * @return Returns TRUE if the buffer is guaranteed to be a single contiguous DMA block, and FALSE otherwise.
 */
uint32_t CC_PalIsDmaBufferContiguous(uint8_t       *pDataBuffer,
				      uint32_t       buffSize)
{
	CC_UNUSED_PARAM(pDataBuffer);
	CC_UNUSED_PARAM(buffSize);
	return 0; // false indication
}

