/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include "ssi_pal_log.h"
#include "cc_plat.h"
#include "ssi_pal_dma.h"
#include "ssi_pal_memmap.h"
#include "ssi_pal_perf.h"
#include <string.h>
#include "ssi_pal_mem.h"

uint32_t gMemBaseAddr        = 0;
static uint32_t gMemNextAddr = 0;

#define DX_PAL_MAX_COOKIES_NUM 260 // 2*FW_MLLI_TABLE_LEN + 10 reserved
#define DX_PAL_MAX_MAP_HANDLE  10  // in case of MLLI we need 3 for inBuff, 3 for outBuff and 4 reserved

#define PAL_PAGE_SHIFT 12
#define PAL_PAGE_SIZE  (1 << PAL_PAGE_SHIFT)
#define PAL_PAGE_MASK  (~(PAL_PAGE_SIZE - 1))

#define DX_PAL_FALSE 0
#define DX_PAL_TRUE  1

#define CACHE_LINE_SIZE           (64)
#define ALIGNED(input, alignment) (((input + alignment - 1) / alignment) * alignment)

typedef struct {
    uint32_t buffSize;
    uint8_t *pVirtBuffAddr;
    uint8_t isTaken;
} DX_PAL_IntDmaMapCookies_t;

typedef struct {
    uint32_t index;
    uint8_t isUsed;
    uint32_t numOfTakenCookies;
    DX_PAL_IntDmaMapCookies_t cookeis[DX_PAL_MAX_COOKIES_NUM];
} DX_PAL_IntDmaMapHandle_t;

static DX_PAL_IntDmaMapHandle_t cookiesDB[DX_PAL_MAX_MAP_HANDLE];

void flush_dcache_range(uint64_t, uint64_t);
void clean_dcache_range(uint64_t, uint64_t);
void inv_dcache_range(uint64_t, uint64_t);

static uint32_t DX_PAL_CalcPageSize(uint32_t index, uint32_t numPages, uint8_t *pDataBuffer, uint32_t buffSize,
                                    uint32_t startOffset)
{
    uint32_t size = 0;

    if (index == 0) {
        if ((PAL_PAGE_SIZE - startOffset) >= buffSize) {
            return buffSize;
        }
        return (PAL_PAGE_SIZE - startOffset);
    }

    if (index == (numPages - 1)) {
        size = ((uint32_t)(pDataBuffer + buffSize)) & (~PAL_PAGE_MASK);
        if (size == 0x0) {
            size = PAL_PAGE_SIZE;
        }
        return size;
    }

    return PAL_PAGE_SIZE;
}

static DX_PAL_IntDmaMapHandle_t *DX_PAL_GetDmaHandle(uint32_t *handle)
{
    uint32_t i;
    for (i = 0; i < DX_PAL_MAX_MAP_HANDLE; i++) {
        if (cookiesDB[i].isUsed == DX_PAL_FALSE) {
            cookiesDB[i].isUsed = DX_PAL_TRUE;
            *handle             = i;
            return &cookiesDB[i];
        }
    }
    return NULL;
}

static void DX_PAL_FreeDmaHandle(uint32_t handle)
{
    if (handle >= DX_PAL_MAX_MAP_HANDLE) {
        return;
    }
    memset((uint8_t *)&cookiesDB[handle].cookeis, 0, sizeof(cookiesDB[handle].cookeis));
    cookiesDB[handle].isUsed = DX_PAL_FALSE;
}

static DX_PAL_IntDmaMapCookies_t *DX_PAL_GetCookie(uint32_t handle, uint32_t *cookieIdx)
{
    uint32_t i;

    if (handle >= DX_PAL_MAX_MAP_HANDLE) {
        return NULL;
    }
    if (cookiesDB[handle].numOfTakenCookies >= DX_PAL_MAX_COOKIES_NUM) {
        return NULL;
    }
    for (i = 0; i < DX_PAL_MAX_COOKIES_NUM; i++) {
        if (cookiesDB[handle].cookeis[i].isTaken == DX_PAL_FALSE) {
            cookiesDB[handle].cookeis[i].isTaken = DX_PAL_TRUE;
            cookiesDB[handle].numOfTakenCookies++;
            *cookieIdx = i;
            return &cookiesDB[handle].cookeis[i];
        }
    }
    return NULL;
}

static DX_PAL_IntDmaMapCookies_t *DX_PAL_GetCookieByIndex(uint32_t handle, uint32_t cookieIndex)
{
    if ((handle >= DX_PAL_MAX_MAP_HANDLE) || (cookieIndex >= DX_PAL_MAX_COOKIES_NUM)) {
        return NULL;
    }
    if (cookiesDB[handle].cookeis[cookieIndex].isTaken == DX_PAL_FALSE) {
        return NULL;
    }
    return &cookiesDB[handle].cookeis[cookieIndex];
}

static uint32_t DX_PAL_ReleaseCookie(uint32_t handle, uint32_t cookieIndex)
{
    if ((handle >= DX_PAL_MAX_MAP_HANDLE) || (cookieIndex >= DX_PAL_MAX_COOKIES_NUM)) {
        return 1;
    }
    if (cookiesDB[handle].cookeis[cookieIndex].isTaken == DX_PAL_FALSE) {
        return 2;
    }
    if (cookiesDB[handle].numOfTakenCookies < 1) {
        return 3;
    }
    cookiesDB[handle].cookeis[cookieIndex].buffSize      = 0;
    cookiesDB[handle].cookeis[cookieIndex].pVirtBuffAddr = NULL;
    cookiesDB[handle].cookeis[cookieIndex].isTaken       = DX_PAL_FALSE;
    cookiesDB[handle].numOfTakenCookies--;
    return 0;
}

static void SaSi_PalInitCookies(void)
{
    uint32_t i = 0;

    memset((uint8_t *)cookiesDB, 0, sizeof(cookiesDB));
    for (i = 0; i < DX_PAL_MAX_MAP_HANDLE; i++) {
        cookiesDB[i].index = i;
    }
}

/* **************************************************************************************************** */
/* ****** Public functions                                                       ********************** */
/* **************************************************************************************************** */

/*
 * @brief  initialize cookies and memory used for dma operations
 *
 * @param[in] buffSize - buffer size in Bytes
 * @param[in] physBuffAddr - physical start address of the memory to map
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t SaSi_PalDmaInit(uint32_t buffSize, uint32_t physBuffAddr)
{
    SASI_UNUSED_PARAM(buffSize);
    gMemBaseAddr = ALIGNED((uint32_t)physBuffAddr, CACHE_LINE_SIZE);
    gMemNextAddr = gMemBaseAddr;
    SaSi_PalInitCookies();
    return 0;
}

/*
 * @brief   free system resources created in PD_PAL_DmaInit()
 *
 * @param[in] buffSize - buffer size in Bytes
 *
 * @return void
 */
void SaSi_PalDmaTerminate(void)
{
    gMemBaseAddr = 0;
    gMemNextAddr = 0;
    return;
}

/*
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
uint32_t SaSi_PalDmaBufferMap(uint8_t *pDataBuffer, uint32_t buffSize, SaSi_PalDmaBufferDirection_t copyDirection,
                              uint32_t *pNumOfBlocks, SaSi_PalDmaBlockInfo_t *pDmaBlockList,
                              SaSi_PalDmaBufferHandle *dmaBuffHandle)
{
    uint32_t retCode = 0;
    uint32_t index = 0, rIndex = 0;
    uint32_t cookie                       = 0;
    uint32_t dmaHandle                    = 0;
    DX_PAL_IntDmaMapHandle_t *plDmaHandle = NULL;
    DX_PAL_IntDmaMapCookies_t *plCookeis  = NULL;
    uint32_t size                         = 0;
    uint32_t endPage                      = 0;
    uint32_t startPage                    = 0;
    uint32_t startOffset                  = 0;
    uint32_t numPages                     = 0;
    uint8_t *pTmpBuff                     = pDataBuffer;
    SaSi_PalPerfData_t perfIdx            = 0;

    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_PAL_MAP);

    if ((pNumOfBlocks == NULL) || (pDmaBlockList == NULL) || (dmaBuffHandle == NULL)) {
        retCode = 1;
        goto pal_mapEnd;
    }
    *(uint32_t *)dmaBuffHandle = 0;
    plDmaHandle                = DX_PAL_GetDmaHandle((uint32_t *)&dmaHandle);
    if (plDmaHandle == NULL) {
        retCode = 2;
        goto pal_mapEnd;
    }

    // calculate number of blocks(pages) held by pDataBuffer
    endPage   = (uint32_t)((pDataBuffer + buffSize) - 1) >> PAL_PAGE_SHIFT;
    startPage = ((uint32_t)pDataBuffer) >> PAL_PAGE_SHIFT;
    numPages  = endPage - startPage + 1;
    if ((numPages == 0) || (numPages > *pNumOfBlocks)) {
        DX_PAL_FreeDmaHandle(dmaHandle);
        retCode = 4;
        goto pal_mapEnd;
    }

    startOffset   = (uint32_t)pDataBuffer & (~PAL_PAGE_MASK);
    *pNumOfBlocks = numPages;
    pTmpBuff      = pDataBuffer;

    // fill rest of the pages in array
    for (index = 0; index < numPages; index++) {
        size = DX_PAL_CalcPageSize(index, numPages, pDataBuffer, buffSize, startOffset);
        // get block's cookie
        plCookeis = DX_PAL_GetCookie(dmaHandle, (uint32_t *)&cookie);
        if (plCookeis == NULL) {
            /* release all the allocated memories and cookies */
            for (rIndex = 0; rIndex < index; rIndex++) {
                plCookeis = DX_PAL_GetCookieByIndex(dmaHandle, rIndex);
                SaSi_PalDmaContigBufferFree(plCookeis->buffSize, (plCookeis->pVirtBuffAddr));
                DX_PAL_ReleaseCookie(dmaHandle, rIndex);
            }
            DX_PAL_FreeDmaHandle(dmaHandle);
            retCode = 5;
            goto pal_mapEnd;
        }
        plCookeis->buffSize      = size;
        plCookeis->pVirtBuffAddr = pTmpBuff;

        pDmaBlockList[index].blockSize     = plCookeis->buffSize;
        pDmaBlockList[index].blockPhysAddr = SaSi_PalMapVirtualToPhysical(pTmpBuff);

        pTmpBuff += pDmaBlockList[index].blockSize;
    }

    *(uint32_t **)dmaBuffHandle = &plDmaHandle->index;

    if (copyDirection == SASI_PAL_DMA_DIR_TO_DEVICE) {
        uint64_t addr = 0;
        SaSi_PalMemCopy(&addr, &pDataBuffer, sizeof(unsigned int));
        clean_dcache_range((uint64_t)addr, (uint64_t)buffSize);

    } else {
        uint64_t addr = 0;
        SaSi_PalMemCopy(&addr, &pDataBuffer, sizeof(unsigned int));
        clean_dcache_range((uint64_t)addr, (uint64_t)buffSize);
        inv_dcache_range((uint64_t)addr, (uint64_t)buffSize);
    }

pal_mapEnd:
    SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_PAL_MAP);
    return retCode;
}

/*
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
uint32_t SaSi_PalDmaBufferUnmap(uint8_t *pDataBuffer, uint32_t buffSize, SaSi_PalDmaBufferDirection_t copyDirection,
                                uint32_t numOfBlocks, SaSi_PalDmaBlockInfo_t *pDmaBlockList,
                                SaSi_PalDmaBufferHandle dmaBuffHandle)
{
    uint32_t retCode                     = 0;
    uint32_t index                       = 0;
    uint32_t dmaHandle                   = 0;
    DX_PAL_IntDmaMapCookies_t *plCookeis = NULL;
    SaSi_PalPerfData_t perfIdx           = 0;

    SASI_UNUSED_PARAM(pDataBuffer);
    SASI_UNUSED_PARAM(buffSize);

    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_PAL_UNMAP);

    if ((pDmaBlockList == NULL) || (dmaBuffHandle == NULL)) {
        retCode = 1;
        goto pal_unmapEnd;
    }
    dmaHandle = *(uint32_t *)dmaBuffHandle;
    if (dmaHandle > DX_PAL_MAX_MAP_HANDLE) {
        retCode = 1;
        goto pal_unmapEnd;
    }
    // free resources
    for (index = 0; index < numOfBlocks; index++) {
        plCookeis = DX_PAL_GetCookieByIndex(dmaHandle, index);
        if (plCookeis == NULL) {
            /* Although this is problem we can't stop as we must clear all cookies */
            retCode = 2;
            continue;
        }

        // if buffer was not allocated/copy in SaSi_PalDmaMap(), nothing left to be doen.Just return OK
        plCookeis->pVirtBuffAddr = NULL;
        plCookeis->buffSize      = 0;
        DX_PAL_ReleaseCookie(dmaHandle, index);
    }
    /* After releasing all cookies we release the dmaHandle */
    DX_PAL_FreeDmaHandle(dmaHandle);

    if (copyDirection != SASI_PAL_DMA_DIR_TO_DEVICE) {
        uint64_t addr = 0;
        SaSi_PalMemCopy(&addr, &pDataBuffer, sizeof(unsigned int));
        clean_dcache_range((uint64_t)addr, (uint64_t)buffSize);
        inv_dcache_range((uint64_t)addr, (uint64_t)buffSize);
    }

pal_unmapEnd:
    SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_PAL_UNMAP);
    return retCode;
}

/*
 * @brief   Allocates a DMA-contiguous buffer, and returns both its physical and virtual addresses
 *
 *
 * @param[in] buffSize - Buffer size in bytes
 * @param[out] ppVirtBuffAddr - Virtual address of the allocated buffer
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t SaSi_PalDmaContigBufferAllocate(uint32_t buffSize, uint8_t **ppVirtBuffAddr)
{
    *ppVirtBuffAddr = (uint8_t *)(gMemNextAddr);
    gMemNextAddr += ALIGNED(buffSize, CACHE_LINE_SIZE);
    ;

    return 0;
}

/*
 * @brief   free resources previuosly allocated by SaSi_PalDmaContigBufferAllocate
 *
 *
 * @param[in] buffSize - buffer size in Bytes
 * @param[in] pVirtBuffAddr - virtual address of the buffer to free
 *
 * @return success/fail
 */
uint32_t SaSi_PalDmaContigBufferFree(uint32_t buffSize, uint8_t *pVirtBuffAddr)
{
    SASI_UNUSED_PARAM(buffSize);
    SASI_UNUSED_PARAM(pVirtBuffAddr);
    return 0;
}

/*
 * @brief   release and free previously allocated buffers
 *
 * @param[in] pDataBuffer - User buffer address
 * @param[in] buffSize - User buffer size
 *
 * @return Returns TRUE if the buffer is guaranteed to be a single contiguous DMA block, and FALSE otherwise.
 */
uint32_t SaSi_PalIsDmaBufferContiguous(uint8_t *pDataBuffer, uint32_t buffSize)
{
    unsigned long bufStartOffset;
    unsigned long bufEndOffset;

    if (buffSize > PAL_PAGE_SIZE) {
        return 0;
    }

    bufStartOffset = (unsigned long)pDataBuffer & (PAL_PAGE_SIZE - 1);
    bufEndOffset   = ((unsigned long)pDataBuffer + buffSize - 1) & (PAL_PAGE_SIZE - 1);

    if (bufStartOffset > bufEndOffset) {
        return 0;
    } else {
        return 1;
    }
}

/*
 * @brief     Maps virtual address to physical address
 *
 * @param[in] pVirtualAddr -   pointer to virtual address
 *
 * @return physical address => assumption , in no_os it is identical to the virtual address
 */
SaSiDmaAddr_t SaSi_PalMapVirtualToPhysical(uint8_t *pVirtualAddr)
{
    return (SaSiDmaAddr_t)(*pVirtualAddr);
}
