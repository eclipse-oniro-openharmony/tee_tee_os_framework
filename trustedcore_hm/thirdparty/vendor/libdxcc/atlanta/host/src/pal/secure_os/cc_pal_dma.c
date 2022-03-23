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
//#include <unistd.h>
//#include <sys/mman.h>
//#include <fcntl.h>
#include "stdlib.h"
#include <string.h>
#include <drv_cache_flush.h> // v7_dma_inv_range
#include "cc_pal_types.h"
#include "cc_plat.h"
#include "cc_pal_dma.h"
#include "bget.h"
#include "dx_crys_kernel.h"
#include "dx_reg_base_host.h"
#include "cc_lli_defs.h"
#include "cc_general_defs.h"
//#include <assert.h>
#include "cc_pal_log_plat.h"
#include "cc_pal_perf.h"
#define tloge(fmt, args...) \
	({\
	 uart_printf_func("%s: " fmt "", __FUNCTION__, ## args);\
	 })

extern void v7_dma_inv_range(unsigned long start, unsigned long end);
extern void v7_dma_flush_range(unsigned long start, unsigned long end);
extern uint64_t virt_mem_to_phys(uint32_t v_addr);
static 	int fd_mem = -1;
CCVirtAddr_t gMemVirtBaseAddr = 0;
CCDmaAddr_t gMemPhysBaseAddr = 0;
unsigned long gMemPoolLen = 0;

typedef enum {
	PAL_DMA_BUFF_TYPE_PHYS = 0,
	PAL_DMA_BUFF_TYPE_NEW_PHYS = 1,
	PAL_DMA_BUFF_TYPE_MAX,
	PAL_DMA_BUFF_TYPE_RESERVE32 = 0x7FFFFFFF
}PAL_DmaBufType_t;

#define PAL_MAX_COOKIES_NUM	260  // 2*FW_MLLI_TABLE_LEN + 10 reserved

#define PAL_IO_MAP_HANDLE   10	// in case of MLLI we need 3 for inBuff, 3 for outBuff and 4 reserved
#define PAL_RPMB_MAP_HANDLE FW_MLLI_TABLE_LEN	// in case of CC_UtilSignRPMBFrames process up to max mlli entries
#define PAL_MAX_MAP_HANDLE   PAL_RPMB_MAP_HANDLE

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
 * @brief   Initializes contiguous memory pool required for CC_PalDmaContigBufferAllocate() and CC_PalDmaContigBufferFree(). Our
 *           implementation is to mmap 0x10000000 and call to bpool(), for use of bget() in CC_PalDmaContigBufferAllocate(),
 *           and brel() in CC_PalDmaContigBufferFree().
 *
 * @param[in] buffSize - buffer size in Bytes
 * @param[in] physBuffAddr - physical start address of the memory to map
 *
 * @return Returns a non-zero value in case of failure
 */
 /*if open LPAE, use 0xa0100000*/
/*for hi3660 hi3650 hi6250 hi3670*/
#define DX_WORK_MEM_VIRT_BASE 0xA0100000
uint32_t CC_PalDmaInit(uint32_t  buffSize,
                        CCDmaAddr_t  physBuffAddr)
{

	(void)buffSize;
#if 0
	unsigned long *pWsBase = NULL, *memBaseAddrArm = NULL;
	int fd_mem_arm = -1;

	if ((fd_mem=open("/dev/mem", O_RDWR|O_SYNC))<0) {
		return (unsigned long)NULL;
	}

	pWsBase = mmap(NULL, buffSize, PROT_READ|PROT_WRITE, MAP_SHARED, fd_mem, physBuffAddr);

	if (pWsBase == MAP_FAILED) {
		return (unsigned long)NULL;
	}
#endif
	gMemVirtBaseAddr = DX_WORK_MEM_VIRT_BASE;
	gMemPhysBaseAddr = physBuffAddr;
	gMemPoolLen = buffSize;

	bpool((void *)gMemVirtBaseAddr, gMemPoolLen);

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
	if (fd_mem < 0) {
		return;
	}
	//munmap((uint32_t *)gMemVirtBaseAddr, gMemPoolLen);
	//close(fd_mem);
	fd_mem = -1;
	gMemVirtBaseAddr = 0;
	gMemPhysBaseAddr = 0;
	gMemPoolLen = 0;
	return;
}

/**
 * @brief 	Maps virtual address to physical address
 *
 * @param[in] pVirtualAddr -   pointer to virtual address
 *
 * @return physical address
 */
static CCDmaAddr_t CC_PalMapVirtualToPhysical(uint8_t *pVirtualAddr)
{
	CCDmaAddr_t physAddr = (CCDmaAddr_t)(( (CCVirtAddr_t)(pVirtualAddr)-gMemVirtBaseAddr )+gMemPhysBaseAddr);

#ifdef DX_PLAT_ZYNQ7000
#if defined CC_DMA_48BIT_SIM
	if(((physAddr >> 4) & 0xF) % 2){
		/* Map addresses 48 bits according to Zynq7000 emulation */
		physAddr =  ( (physAddr&0xffff0000)<<16 | 0xffff0000 | (physAddr&0xffff) );
	}
#endif
#endif
    return physAddr;

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

		/* Assert size of buffer in case of MLLI */
		//assert (plCookeis->buffSize <= (0x1UL << LLI_SIZE_BIT_SIZE));
		pDmaBlockList[index].blockSize = plCookeis->buffSize;
		pDmaBlockList[index].blockPhysAddr = virt_mem_to_phys(pTmpBuff);
		v7_dma_flush_range(pTmpBuff, pTmpBuff + pDmaBlockList[index].blockSize);


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
	v7_dma_inv_range(pDataBuffer, pDataBuffer+buffSize);
pal_unmapEnd:
	CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_PAL_UNMAP);
	return retCode;
}



/**
 * @brief   Allocates a DMA-contiguous buffer, and returns its virtual address. the address must be 32 bits aligned.
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

	*ppVirtBuffAddr = (uint8_t *)bgetz(buffSize);

	if (NULL == *ppVirtBuffAddr) {
		return 1;
	}
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
	buffSize = buffSize;
	// check input validity
	if (NULL == pVirtBuffAddr) {
		return 1;
	}
	// release buffer from pool
	brel((void *)pVirtBuffAddr);
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
	(void)pDataBuffer;
	(void)buffSize;
	return 0;
}


