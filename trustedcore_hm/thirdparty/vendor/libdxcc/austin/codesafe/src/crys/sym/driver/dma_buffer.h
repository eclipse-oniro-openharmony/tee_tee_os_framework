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

#ifndef __DMA_BUFFER_H__
#define __DMA_BUFFER_H__

#include <stdint.h>
#include "dma_buffer_plat.h"
#include "cc_plat.h"

/* Get the DmaMode_t to match DMA buffer type */
#define DMA_BUF_TYPE_TO_MODE(dmaBufType) \
    (((dmaBufType) == DMA_BUF_NULL) ?    \
         NO_DMA :                        \
         ((dmaBufType) == DMA_BUF_SEP) ? DMA_SRAM : ((dmaBufType) == DMA_BUF_DLLI) ? DMA_DLLI : DMA_MLLI)

/* DMA buffer type */
typedef enum DmaBufType {
    DMA_BUF_NULL = 0,
    DMA_BUF_SEP,
    DMA_BUF_DLLI,
    DMA_BUF_MLLI_IN_SEP,
    DMA_BUF_MLLI_IN_HOST
} DmaBufType_t;

typedef struct DmaBuffer {
    DmaBufType_t dmaBufType;
    DxDmaAddr_t pData; /* A pointer to the data (DMA_SRAM/DLLI) or MLLI table (DMA_MLLI_*) */
    uint32_t size;     /* The size of the data (DMA_SRAM/DLLI) or size of first MLLI table (DMA_MLLI_*) */
    uint8_t axiNs;     /* AXI NS bit */
} DmaBuffer_s;

/* !
 * Parse user buffer information that may be smart-pointer (DMA object/buffer)
 * Return uniform DMA information
 *
 * \param dataPtr Pointer given by the user
 * \param dataSize Data size given by the user (relevant for non-smart-ptr)
 * \param pDmaType
 * \param pDmaAddr
 * \param pDmaSize
 * \param pDmaAxiNs The AXI Secure bit
 *
 * \return 0 on success, !0 if parameter are invalid (e.g., dataSize != dma object data size)
 */
int dataPtrToDma(uint8_t *dataPtr, uint32_t dataSize, DmaBufType_t *pDmaType, uint32_t *pDmaAddr, uint32_t *pDmaSize,
                 uint32_t *pDmaAxiNs);

/* !
 * validate DMA object structure
 *
 * \param dmaObj the DMA object
 * \param dataSize Data size given by the user (relevent only for SRAM data)
 *
 * \return 0 on success, (-1) if ( dataSize != dma object data size), (-2) if sram pointer is out of range
 */
int validateDmaBuffer(DmaBuffer_s *dmaObj, uint32_t dataSize);

#endif /* __DMA_BUFFER_H__ */
