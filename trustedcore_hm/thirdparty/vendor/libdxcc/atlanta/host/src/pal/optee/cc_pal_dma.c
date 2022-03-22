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
#include <stdlib.h>
#include <mm/core_memprot.h>
#include <kernel/thread.h>
#include <trace.h>
#include "cc_pal_types.h"
#include "cc_pal_dma.h"
#include "cc_general_defs.h"

static uint32_t cache_operation(enum utee_cache_operation op, void *va, size_t len)
{
	TEE_Result ret;
	paddr_t pa = 0;

	pa = virt_to_phys(va);
	if (!pa)
		return 1;

	switch (op) {
	case TEE_CACHEFLUSH:
		/* Clean L1, Flush L2, Flush L1 */
		ret = cache_maintenance_l1(DCACHE_AREA_CLEAN, va, len);
		if (ret != TEE_SUCCESS)
			return 1;
		ret = cache_maintenance_l2(L2CACHE_AREA_CLEAN_INV, pa, len);
		if (ret != TEE_SUCCESS)
			return 1;
		return cache_maintenance_l1(DCACHE_AREA_CLEAN_INV, va, len);

	case TEE_CACHECLEAN:
		/* Clean L1, Clean L2 */
		ret = cache_maintenance_l1(DCACHE_AREA_CLEAN, va, len);
		if (ret != TEE_SUCCESS)
			return 1;
		return cache_maintenance_l2(L2CACHE_AREA_CLEAN, pa, len);

	case TEE_CACHEINVALIDATE:
		/* Inval L2, Inval L1 */
		ret = cache_maintenance_l2(L2CACHE_AREA_INVALIDATE, pa, len);
		if (ret != TEE_SUCCESS)
			return 1;
		return cache_maintenance_l1(DCACHE_AREA_INVALIDATE, va, len);

	default:
		return /*TEE_ERROR_NOT_SUPPORTED*/1;
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
uint32_t CC_PalDmaInit(uint32_t  buffSize,
		       CCDmaAddr_t  physBuffAddr)
{

	CC_UNUSED_PARAM(buffSize);
	CC_UNUSED_PARAM(physBuffAddr);

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
	CCDmaAddr_t physAddr = (CCDmaAddr_t)virt_to_phys(pVirtualAddr);

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
uint32_t CC_PalDmaBufferMap(uint8_t                       *pDataBuffer,
			    uint32_t                     buffSize,
			    CCPalDmaBufferDirection_t  copyDirection,
			    uint32_t                     *pNumOfBlocks,
			    CCPalDmaBlockInfo_t        *pDmaBlockList,
			    CC_PalDmaBufferHandle       *dmaBuffHandle)
{
	CC_UNUSED_PARAM(copyDirection);
	CC_UNUSED_PARAM(dmaBuffHandle);

	if ((NULL == pNumOfBlocks) || (0 == *pNumOfBlocks) || (NULL == pDmaBlockList)) {
		return 1;
	}

	if (cache_operation(TEE_CACHEFLUSH, pDataBuffer, buffSize) != TEE_SUCCESS) {
		EMSG("cache_operation (TEE_CACHEFLUSH) failed. pDataBuffer=%p, buffSize=%d", pDataBuffer, (int)buffSize);
		return 1;
	}
	pDmaBlockList[0].blockPhysAddr = CC_PalMapVirtualToPhysical(pDataBuffer);
	pDmaBlockList[0].blockSize = buffSize;
	*pNumOfBlocks = 1;

	return 0;
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
uint32_t CC_PalDmaBufferUnmap(uint8_t                       *pDataBuffer,
			      uint32_t                     buffSize,
			      CCPalDmaBufferDirection_t  copyDirection,
			      uint32_t                     numOfBlocks,
			      CCPalDmaBlockInfo_t        *pDmaBlockList,
			      CC_PalDmaBufferHandle       dmaBuffHandle)
{
	CC_UNUSED_PARAM(copyDirection);
	CC_UNUSED_PARAM(numOfBlocks);
	CC_UNUSED_PARAM(pDmaBlockList);
	CC_UNUSED_PARAM(dmaBuffHandle);

	if (cache_operation(TEE_CACHEINVALIDATE, pDataBuffer, buffSize) != TEE_SUCCESS) {
		EMSG("cache_operation (TEE_CACHEINVALIDATE) failed");
		return 1;
	}

	return 0;
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
	*ppVirtBuffAddr = (uint8_t *)malloc(buffSize);

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
	CC_UNUSED_PARAM(buffSize);
	// check input validity
	if (NULL == pVirtBuffAddr) {
		return 1;
	}
	// release buffer from pool
	free((void *)pVirtBuffAddr);
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
	if (malloc_buffer_overlaps_heap(pDataBuffer, buffSize)) {
		return 1;
	}

	return 0;
}


