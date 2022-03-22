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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bits/alltypes.h>

#include <mem_ops_ext.h> // for __virt_to_phys()

#include "bget.h"
#include "dx_crys_kernel.h"
#include "dx_reg_base_host.h"
#include "dx_pal_dma.h"
#include "dx_pal_memmap.h"

// hmos function
#include <hm_stdint.h> // for ptr_to_uint64()
#include "hm_mman_ext.h"   // for hm_mmap_physical()
extern void __dma_map_area(uintptr_t start, uintptr_t size, int dir);
extern void __dma_unmap_area(uintptr_t start, uintptr_t size, int dir);
extern void uart_printf_func(const char *fmt, ...);
#define tloge uart_printf_func
// ----

unsigned long gMemVirtBaseAddr = 0;
unsigned long gMemPhysBaseAddr = 0;
unsigned long gMemPoolLen      = 0;

#define DX_PAL_MAX_COOKIES_NUM 260 // 2*FW_MLLI_TABLE_LEN + 10 reserved
#define DX_PAL_MAX_MAP_HANDLE  10  // in case of MLLI we need 3 for inBuff, 3 for outBuff and 4 reserved

#define PAL_PAGE_SHIFT 12
#define PAL_PAGE_SIZE  (1 << PAL_PAGE_SHIFT)
#define PAL_PAGE_MASK  (~(PAL_PAGE_SIZE - 1))

#define DX_PAL_FALSE 0
#define DX_PAL_TRUE  1

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

static void DX_PAL_InitCookies()
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
 * @return Virtual start address of contiguous memory
 */
uint32_t dx_pal_dma_init(uint32_t buff_size)
{
    gMemVirtBaseAddr = (DxVirtAddr_t)malloc_coherent(buff_size);
    if (gMemVirtBaseAddr == 0)
        return 1;

    gMemPhysBaseAddr = __virt_to_phys(gMemVirtBaseAddr);
    gMemPoolLen      = buff_size;

    bpool((void *)gMemVirtBaseAddr, gMemPoolLen);

    DX_PAL_InitCookies();

    return gMemVirtBaseAddr;
}

/*
 * @brief   free system resources created in PD_PAL_DmaInit()
 *
 * @param[in] buffSize - buffer size in Bytes
 *
 * @return void
 */
void DX_PAL_DmaTerminate()
{
    munmap((uint32_t *)gMemVirtBaseAddr, gMemPoolLen);
    gMemVirtBaseAddr = 0;
    gMemPhysBaseAddr = 0;
    gMemPoolLen      = 0;
}

/*
 * @brief     Maps virtual address to physical address
 *
 * @param[in] pVirtualAddr -   pointer to virtual address
 *
 * @return physical address
 */
DxDmaAddr_t DX_PAL_MapVirtualToPhysical(uint8_t *pVirtualAddr)
{
    if ((pVirtualAddr >= gMemVirtBaseAddr) && (pVirtualAddr <= gMemVirtBaseAddr + gMemPoolLen)) {
        return (DxDmaAddr_t)(((DxDmaAddr_t)ptr_to_uint64(pVirtualAddr) - gMemVirtBaseAddr) + gMemPhysBaseAddr);
    }
    return (DxDmaAddr_t)__virt_to_phys((uint32_t)pVirtualAddr);
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
uint32_t DX_PAL_DmaBufferMap(uint8_t *pDataBuffer, uint32_t buffSize, DX_PAL_DmaBufferDirection_t copyDirection,
                             uint32_t *pNumOfBlocks, DX_PAL_DmaBlockInfo_t *pDmaBlockList,
                             DX_PAL_DmaBufferHandle *dmaBuffHandle)
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

    if ((pNumOfBlocks == NULL) || (pDmaBlockList == NULL) || (dmaBuffHandle == NULL) || (*pNumOfBlocks < 1)) {
        retCode = 1;
        goto pal_mapEnd;
    }
    *(uint32_t *)dmaBuffHandle = 0;
    plDmaHandle                = DX_PAL_GetDmaHandle((uint32_t *)&dmaHandle);
    if (plDmaHandle == NULL) {
        retCode = 2;
        goto pal_mapEnd;
    }

    // First check whether pDataBuffer is contiguous
    if (DX_PAL_IsDmaBufferContiguous(pDataBuffer, buffSize)) {
        plCookeis = DX_PAL_GetCookie(dmaHandle, (uint32_t *)&cookie);
        if (plCookeis == NULL) {
            DX_PAL_FreeDmaHandle(dmaHandle);
            return 3;
        }
        plCookeis->pVirtBuffAddr       = pDataBuffer;
        plCookeis->buffSize            = buffSize;
        *pNumOfBlocks                  = 1;
        pDmaBlockList[0].blockPhysAddr = DX_PAL_MapVirtualToPhysical(pDataBuffer);
        pDmaBlockList[0].blockSize     = buffSize;
        goto pal_mapFinish;
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
                DX_PAL_DmaContigBufferFree(plCookeis->buffSize, (plCookeis->pVirtBuffAddr));
                DX_PAL_ReleaseCookie(dmaHandle, rIndex);
            }
            DX_PAL_FreeDmaHandle(dmaHandle);
            retCode = 5;
            goto pal_mapEnd;
        }
        plCookeis->buffSize      = size;
        plCookeis->pVirtBuffAddr = pTmpBuff;

        /* Assert size of buffer in case of MLLI */
        pDmaBlockList[index].blockSize     = plCookeis->buffSize;
        pDmaBlockList[index].blockPhysAddr = __virt_to_phys(pTmpBuff);

        pTmpBuff += pDmaBlockList[index].blockSize;
    }

pal_mapFinish:
#ifdef CONFIG_ARM32_FLUSH_CACHE
    v7_dma_flush_range(pDataBuffer, pDataBuffer + buffSize);
#else
    __dma_map_area((uint32_t)pDataBuffer, buffSize, copyDirection);
#endif
    *(uint32_t **)dmaBuffHandle = &plDmaHandle->index;

pal_mapEnd:
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
uint32_t DX_PAL_DmaBufferUnmap(uint8_t *pDataBuffer, uint32_t buffSize, DX_PAL_DmaBufferDirection_t copyDirection,
                               uint32_t numOfBlocks, DX_PAL_DmaBlockInfo_t *pDmaBlockList,
                               DX_PAL_DmaBufferHandle dmaBuffHandle)
{
    uint32_t retCode                     = 0;
    uint32_t index                       = 0;
    uint32_t dmaHandle                   = 0;
    DX_PAL_IntDmaMapCookies_t *plCookeis = NULL;

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

        // if buffer was not allocated/copy in DX_PAL_DmaBufferMap(), nothing left to be doen.Just return OK
        plCookeis->pVirtBuffAddr = NULL;
        plCookeis->buffSize      = 0;
        DX_PAL_ReleaseCookie(dmaHandle, index);
    }
    /* After releasing all cookies we release the dmaHandle */
    DX_PAL_FreeDmaHandle(dmaHandle);
#ifdef CONFIG_ARM32_FLUSH_CACHE
    v7_dma_flush_range(pDataBuffer, pDataBuffer + buffSize);
#else
    __dma_unmap_area((uint32_t)pDataBuffer, buffSize, copyDirection);
#endif
pal_unmapEnd:
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
uint32_t DX_PAL_DmaContigBufferAllocate(uint32_t buffSize, uint8_t **ppVirtBuffAddr)
{
    *ppVirtBuffAddr = (uint8_t *)bgetz(buffSize);

    if (*ppVirtBuffAddr == NULL) {
        return 1;
    }
    return 0;
}

/*
 * @brief   free resources previuosly allocated by DX_PAL_DmaContigBufferAllocate
 *
 *
 * @param[in] buffSize - buffer size in Bytes
 * @param[in] pVirtBuffAddr - virtual address of the buffer to free
 *
 * @return success/fail
 */
uint32_t DX_PAL_DmaContigBufferFree(uint32_t buffSize, uint8_t *pVirtBuffAddr)
{
    buffSize = buffSize;
    // check input validity
    if (pVirtBuffAddr == NULL) {
        return 1;
    }
    // release buffer from pool
    brel((void *)pVirtBuffAddr);
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
uint32_t DX_PAL_IsDmaBufferContiguous(uint8_t *pDataBuffer, uint32_t buffSize)
{
    uint32_t start = (uint32_t)pDataBuffer;
    uint32_t end   = start + buffSize - 1;

    // within one page
    if ((start >> PAL_PAGE_SHIFT) == (end >> PAL_PAGE_SHIFT)) {
        return 1;
    }

    // for internal buffer, always contiguous
    if ((start >= gMemVirtBaseAddr) && (end <= gMemVirtBaseAddr + gMemPoolLen)) {
        return 1;
    }

    if ((__virt_to_phys(start) + buffSize - 1) != __virt_to_phys(end)) {
        return 0;
    }

    // WARNING
    // TODO: we have to check each page to make sure the buffer is contiguous.

    return 0;
}
