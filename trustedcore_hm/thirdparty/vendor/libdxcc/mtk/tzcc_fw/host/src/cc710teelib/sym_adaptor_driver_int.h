/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SYM_ADAPTOR_DRIVER_INT_H
#define _SYM_ADAPTOR_DRIVER_INT_H

/* *****************************************************************************
 *                            DEFINITIONS
 * *************************************************************************** */

#define MAX_TAIL_BUFF_SIZE (max(MIN_CRYPTO_TAIL_SIZE, DLLI_MAX_BUFF_SIZE))

#define SET_DMA_WITH_DLLI(pDmaBuff, physAddr, buffSize) \
    {                                                   \
        pDmaBuff->pData      = physAddr;                \
        pDmaBuff->size       = buffSize;                \
        pDmaBuff->dmaBufType = DMA_BUF_DLLI;            \
        pDmaBuff->axiNs      = AXI_SECURE;              \
    }

#define SET_DMA_WITH_NULL(pDmaBuff)          \
    {                                        \
        pDmaBuff->pData      = 0;            \
        pDmaBuff->size       = 0;            \
        pDmaBuff->dmaBufType = DMA_BUF_NULL; \
        pDmaBuff->axiNs      = AXI_SECURE;   \
    }

#define SET_DMA_WITH_MLLI(pDmaBuff, physAddr, buffSize) \
    {                                                   \
        pDmaBuff->pData      = physAddr;                \
        pDmaBuff->size       = buffSize;                \
        pDmaBuff->dmaBufType = DMA_BUF_MLLI_IN_HOST;    \
        pDmaBuff->axiNs      = AXI_SECURE;              \
    }

#define COPY_DMA_BUFF(dmaDest, dmaSrc)          \
    {                                           \
        dmaDest.pData      = dmaSrc.pData;      \
        dmaDest.size       = dmaSrc.size;       \
        dmaDest.dmaBufType = dmaSrc.dmaBufType; \
        dmaDest.axiNs      = dmaSrc.axiNs;      \
    }

typedef enum {
    DMA_BUILT_FLAG_NONE        = 0x0,
    DMA_BUILT_FLAG_BI_DIR      = 0x1,
    DMA_BUILT_FLAG_INPUT_BUFF  = 0x2,
    DMA_BUILT_FLAG_OUTPUT_BUFF = 0x4
} eDmaBuiltFlag_t;

typedef struct {
    uint32_t lliEntry[2];
} lliInfo_t;

typedef struct {
    SaSi_PalDmaBlockInfo_t mlliBlockInfo;
    lliInfo_t *pLliEntry;
} mlliTable_t;

typedef struct {
    uint32_t numOfBlocks;
    SaSi_PalDmaBlockInfo_t pBlockEntry[FW_MLLI_TABLE_LEN];
} dmaBuffBlocksInfo_t;

typedef struct {
    uint8_t *pVirtBuffer;
} tailBuffInfo_t;

typedef struct {
    mlliTable_t devBuffer;
    tailBuffInfo_t tailBuff;
    dmaBuffBlocksInfo_t blocksList;
    SaSi_PalDmaBufferHandle buffMainH;
    SaSi_PalDmaBufferHandle buffTailH;
    SaSi_PalDmaBufferHandle buffMlliH;
} interDmaBuildBuffer_t;

enum dx_driver_adaptor_dir { dx_driver_adaptor_in, dx_driver_adaptor_out };

#define SINGLE_BLOCK_ENTRY 1

typedef enum {
    UNMAP_FLAG_NONE            = 0x0,
    UNMAP_FLAG_CONTIG_DLLI     = 0x1,
    UNMAP_FLAG_SMALL_SIZE_DLLI = 0x2,
    UNMAP_FLAG_MLLI_MAIN       = 0x4,
    UNMAP_FLAG_MLLI_TAIL       = 0x8,
    UNMAP_FLAG_MLLI_TABLE      = 0x10
} eUnmapFlag_t;

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */

uint32_t symDriverAdaptorCopyCtx(enum dx_driver_adaptor_dir dir, DxSramAddr_t sram_address,
                                 struct drv_ctx_generic *pCtx);

uint32_t allocDmaBuildBuffers(interDmaBuildBuffer_t *pDmaBuildBuff);

#endif /* _SYM_ADAPTOR_DRIVER_INT_H */
