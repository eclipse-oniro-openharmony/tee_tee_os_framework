/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include "ssi_pal_types.h"
#include "cc_plat.h"
#include "ssi_pal_dma.h"
#include "bget.h"
#include "dx_sasi_kernel.h"
#include "dx_reg_base_host.h"
#include "ssi_lli_defs.h"
#include <assert.h>

static int fd_mem              = -1;
unsigned long gMemVirtBaseAddr = 0;
unsigned long gMemPhysBaseAddr = 0;
unsigned long gMemPoolLen      = 0;

typedef enum {
    DX_PAL_DMA_BUFF_TYPE_PHYS     = 0,
    DX_PAL_DMA_BUFF_TYPE_NEW_PHYS = 1,
    DX_PAL_DMA_BUFF_TYPE_MAX,
    DX_PAL_DMA_BUFF_TYPE_RESERVE32 = 0x7FFFFFFF
} DX_PAL_DmaBufType_t;

#define DX_PAL_MAX_COOKIES_NUM 260 // 2*FW_MLLI_TABLE_LEN + 10 reserved

#define DX_PAL_IO_MAP_HANDLE   10                // in case of MLLI we need 3 for inBuff, 3 for outBuff and 4 reserved
#define DX_PAL_RPMB_MAP_HANDLE FW_MLLI_TABLE_LEN // in case of SaSi_UtilSignRPMBFrames process up to max mlli entries
#define DX_PAL_MAX_MAP_HANDLE  DX_PAL_RPMB_MAP_HANDLE

#define PAL_PAGE_SHIFT 12
#define PAL_PAGE_SIZE  (1 << PAL_PAGE_SHIFT)
#define PAL_PAGE_MASK  (~(PAL_PAGE_SIZE - 1))

#define DX_PAL_FALSE 0
#define DX_PAL_TRUE  1

typedef struct {
    uint32_t buffSize;
    uint8_t *pVirtBuffAddr;
    DX_PAL_DmaBufType_t buffType;
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
        size = ((unsigned long)(pDataBuffer + buffSize)) & ((unsigned long)(~((unsigned long)PAL_PAGE_MASK)));
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
    cookiesDB[handle].cookeis[cookieIndex].buffType      = 0;
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
 * @brief   Initializes contiguous memory pool required for SaSi_PalDmaContigBufferAllocate() and
 * SaSi_PalDmaContigBufferFree(). Our implementation is to mmap 0x10000000 and call to bpool(), for use of bget() in
 * SaSi_PalDmaContigBufferAllocate(), and brel() in SaSi_PalDmaContigBufferFree().
 *
 * @param[in] buffSize - buffer size in Bytes
 * @param[in] physBuffAddr - physical start address of the memory to map
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t SaSi_PalDmaInit(uint32_t buffSize, uint32_t physBuffAddr)
{
    unsigned long *pWsBase = NULL, *memBaseAddrArm = NULL;
    int fd_mem_arm = -1;

    if ((fd_mem = open("/dev/mem", O_RDWR | O_SYNC)) < 0) {
        return (unsigned long)NULL;
    }

    pWsBase = mmap(NULL, buffSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd_mem, physBuffAddr);

    if (pWsBase == MAP_FAILED) {
        return (unsigned long)NULL;
    }

    gMemVirtBaseAddr = (unsigned long)pWsBase;
    gMemPhysBaseAddr = physBuffAddr;
    gMemPoolLen      = buffSize;

    bpool((void *)gMemVirtBaseAddr, gMemPoolLen);

    SaSi_PalInitCookies();

#if (DX_PLAT_ZYNQ7000)
    /* Write to TZ_DDR_RAM in address 0xF8000430, this writing sets the DRAM to be secure for addresses 0x34000000 and
     * up */
    /* Each bit in this register represents 64MB (i.e., bit 0 for range 0-64MB, bit 1 for 64MB-128MB, etc.).
       When a bit is set to 1 that region is insecure (like NS bit) */
    if ((fd_mem_arm = open("/dev/mem", O_RDWR | O_SYNC)) < 0) {
        return (unsigned long)NULL;
    }
    /* mapping of the ARM registers can fail but it shouldnt fail the function -so we ignore it here */
    memBaseAddrArm = mmap(NULL, 0x100000, PROT_READ | PROT_WRITE, MAP_SHARED, fd_mem_arm, 0xF8000000);
    *((uint32_t *)(memBaseAddrArm + 0x430)) = 0x00001FFF;

    /* unmap the memory */
    munmap((uint32_t *)memBaseAddrArm, 0x100000);
    close(fd_mem_arm);
    fd_mem_arm = -1;
#endif

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
    if (fd_mem < 0) {
        return;
    }
    munmap((uint32_t *)gMemVirtBaseAddr, gMemPoolLen);
    close(fd_mem);
    fd_mem           = -1;
    gMemVirtBaseAddr = 0;
    gMemPhysBaseAddr = 0;
    gMemPoolLen      = 0;
    return;
}

/*
 * @brief     Maps virtual address to physical address
 *
 * @param[in] pVirtualAddr -   pointer to virtual address
 *
 * @return physical address
 */
SaSiDmaAddr_t SaSi_PalMapVirtualToPhysical(uint8_t *pVirtualAddr)
{
    SaSiDmaAddr_t physAddr = (SaSiDmaAddr_t)(((unsigned long)(pVirtualAddr)-gMemVirtBaseAddr) + gMemPhysBaseAddr);

#if (DX_PLAT_ZYNQ7000)
#if defined DX_DMA_48BIT_SIM
    if (((physAddr >> 4) & 0xF) % 2) {
        /* Map addresses 48 bits according to Zynq7000 emulation */
        physAddr = ((physAddr & 0xffff0000) << 16 | 0xffff0000 | (physAddr & 0xffff));
    }
#endif
#endif
    return physAddr;
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

    if ((pNumOfBlocks == NULL) || (pDmaBlockList == NULL) || (dmaBuffHandle == NULL)) {
        return 1;
    }
    *(uint32_t *)dmaBuffHandle = 0;
    plDmaHandle                = DX_PAL_GetDmaHandle((uint32_t *)&dmaHandle);
    if (plDmaHandle == NULL) {
        return 2;
    }
    // First check whether pDataBuffer is already mapped to physical contiguous memory defined in SaSi_PalDmaInit()
    if ((pDataBuffer >= (uint8_t *)gMemVirtBaseAddr) && (pDataBuffer < ((uint8_t *)gMemVirtBaseAddr + gMemPoolLen))) {
        plCookeis = DX_PAL_GetCookie(dmaHandle, (uint32_t *)&cookie);
        if (plCookeis == NULL) {
            DX_PAL_FreeDmaHandle(dmaHandle);
            return 3;
        }
        plCookeis->pVirtBuffAddr       = pDataBuffer;
        plCookeis->buffSize            = buffSize;
        plCookeis->buffType            = DX_PAL_DMA_BUFF_TYPE_PHYS;
        *pNumOfBlocks                  = 1;
        pDmaBlockList[0].blockPhysAddr = SaSi_PalMapVirtualToPhysical(pDataBuffer);
        /* Assert size of buffer in case of DLLI */
        assert(buffSize < (0x1UL << DX_DSCRPTR_QUEUE0_WORD1_DIN_SIZE_BIT_SIZE));
        pDmaBlockList[0].blockSize  = buffSize;
        *(uint32_t **)dmaBuffHandle = &plDmaHandle->index;
        return 0;
    }

    // calculate number of blocks(pages) held by pDataBuffer
    endPage   = (unsigned long)((pDataBuffer + buffSize) - 1) >> PAL_PAGE_SHIFT;
    startPage = ((unsigned long)pDataBuffer) >> PAL_PAGE_SHIFT;
    numPages  = endPage - startPage + 1;
    if ((numPages == 0) || (numPages > *pNumOfBlocks)) {
        DX_PAL_FreeDmaHandle(dmaHandle);
        return 4;
    }

    startOffset   = (unsigned long)pDataBuffer & (~PAL_PAGE_MASK);
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
                if (plCookeis != NULL) {
                    SaSi_PalDmaContigBufferFree(plCookeis->buffSize, (plCookeis->pVirtBuffAddr));
                }
                DX_PAL_ReleaseCookie(dmaHandle, rIndex);
            }
            DX_PAL_FreeDmaHandle(dmaHandle);
            return 5;
        }
        plCookeis->buffSize = size;
        // if we got here pDataBuffer is not mapped to physical contiguous memory,
        // so we have to allocate it with in pool and copy buffer according to copyDirection
        retCode = SaSi_PalDmaContigBufferAllocate(plCookeis->buffSize, &(plCookeis->pVirtBuffAddr));
        if (retCode != 0) {
            /* release all the allocated memories and cookies */
            for (rIndex = 0; rIndex < index; rIndex++) {
                plCookeis = DX_PAL_GetCookieByIndex(dmaHandle, rIndex);
                if (plCookeis != NULL) {
                    SaSi_PalDmaContigBufferFree(plCookeis->buffSize, (plCookeis->pVirtBuffAddr));
                }
                DX_PAL_ReleaseCookie(dmaHandle, rIndex);
            }
            DX_PAL_ReleaseCookie(dmaHandle, cookie);
            DX_PAL_FreeDmaHandle(dmaHandle);
            return retCode;
        }

        plCookeis->buffType = DX_PAL_DMA_BUFF_TYPE_NEW_PHYS;
        /* Assert size of buffer in case of MLLI */
        assert(plCookeis->buffSize <= (0x1UL << LLI_SIZE_BIT_SIZE));
        pDmaBlockList[index].blockSize     = plCookeis->buffSize;
        pDmaBlockList[index].blockPhysAddr = SaSi_PalMapVirtualToPhysical(plCookeis->pVirtBuffAddr);
        // now copy according to copy direction
        if ((copyDirection == SASI_PAL_DMA_DIR_TO_DEVICE) || (copyDirection == SASI_PAL_DMA_DIR_BI_DIRECTION)) {
            memcpy((uint8_t *)(plCookeis->pVirtBuffAddr), (uint8_t *)pTmpBuff, plCookeis->buffSize);
        }

        pTmpBuff += pDmaBlockList[index].blockSize;
    }

    *(uint32_t **)dmaBuffHandle = &plDmaHandle->index;
    return 0;
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
    uint32_t retCode = 0;
    uint32_t index   = 0;
    uint8_t *pTmpBuff;
    uint32_t dmaHandle                   = 0;
    DX_PAL_IntDmaMapCookies_t *plCookeis = NULL;

    pTmpBuff = pDataBuffer;
    buffSize = buffSize;

    if ((pDmaBlockList == NULL) || (dmaBuffHandle == NULL)) {
        return 1;
    }
    dmaHandle = *(uint32_t *)dmaBuffHandle;
    if (dmaHandle > DX_PAL_MAX_MAP_HANDLE) {
        return 1;
    }
    // free resources
    for (index = 0; index < numOfBlocks; index++) {
        plCookeis = DX_PAL_GetCookieByIndex(dmaHandle, index);
        if (plCookeis == NULL) {
            /* Although this is problem we can't stop as we must clear all cookies */
            retCode = 2;
            continue;
        }
        // First make sure pCookies-> virtBuffAddr is mapped to physical contiguous memory.
        // Otherwise return error.
        if (((plCookeis->pVirtBuffAddr) < (uint8_t *)gMemVirtBaseAddr) ||
            ((plCookeis->pVirtBuffAddr) >= ((uint8_t *)(gMemVirtBaseAddr + gMemPoolLen)))) {
            /* Although we can't handle this memory (as it is not part of the PAL region ) */
            /* We must proceed with the cookies release */
            DX_PAL_ReleaseCookie(dmaHandle, index);
            retCode = 3;
            continue;
        }

        if (plCookeis->buffType == DX_PAL_DMA_BUFF_TYPE_NEW_PHYS) {
            // in that case have to copy buffer according to copyDirection and free allocated buffer
            if ((copyDirection == SASI_PAL_DMA_DIR_FROM_DEVICE) || (copyDirection == SASI_PAL_DMA_DIR_BI_DIRECTION)) {
                memcpy((uint8_t *)pTmpBuff, (uint8_t *)(plCookeis->pVirtBuffAddr), plCookeis->buffSize);
            }
            // if we got here pDataBuffer is not mapped to physical contiguous memory,
            // so we have to allocate it with in pool and copy buffer according to copyDirection
            SaSi_PalDmaContigBufferFree(plCookeis->buffSize, (plCookeis->pVirtBuffAddr));
        }

        // if buffer was not allocated/copy in SaSi_PalDmaMap(), nothing left to be doen.Just return OK
        plCookeis->buffType      = DX_PAL_DMA_BUFF_TYPE_RESERVE32;
        plCookeis->pVirtBuffAddr = NULL;
        pTmpBuff += plCookeis->buffSize;
        DX_PAL_ReleaseCookie(dmaHandle, index);
    }
    /* After releasing all cookies we release the dmaHandle */
    DX_PAL_FreeDmaHandle(dmaHandle);
    return retCode;
}

/*
 * @brief   Allocates a DMA-contiguous buffer, and returns its virtual address. the address must be 32 bits aligned.
 *
 *
 * @param[in] buffSize - Buffer size in bytes
 * @param[out] ppVirtBuffAddr - Virtual address of the allocated buffer
 *
 * @return Returns a non-zero value in case of failure
 */
uint32_t SaSi_PalDmaContigBufferAllocate(uint32_t buffSize, uint8_t **ppVirtBuffAddr)
{
    *ppVirtBuffAddr = (uint8_t *)bgetz(buffSize);

    if (*ppVirtBuffAddr == NULL) {
        return 1;
    }
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
