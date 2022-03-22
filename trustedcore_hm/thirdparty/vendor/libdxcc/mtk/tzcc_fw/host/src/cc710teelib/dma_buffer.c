/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_INFRA

#include "ssi_pal_log.h"
#include "dma_buffer.h"
#include "hw_queue_defs.h"

#if (DX_DSCRPTR_QUEUE0_WORD3_NS_BIT_BIT_SHIFT != DX_DSCRPTR_QUEUE0_WORD1_NS_BIT_BIT_SHIFT) || \
    (DX_DSCRPTR_QUEUE0_WORD1_DIN_VIRTUAL_HOST_BIT_SHIFT != DX_DSCRPTR_QUEUE0_WORD3_DOUT_VIRTUAL_HOST_BIT_SHIFT)
#error AxiId/NS-bit fields mismatch between DIN and DOUT - functions need to be updated...
#endif

/* !
 * validate DMA object structure
 *
 * \param dmaObj the DMA object
 * \param dataSize Data size given by the user (relevent only for SRAM data)
 *
 * \return 0 on success, (-1) if ( dataSize != dma object data size), (-2) if sram pointer is out of range
 */

int validateDmaBuffer(DmaBuffer_s *dmaObj, uint32_t dataSize)

{
    if ((dmaObj->dmaBufType != DMA_BUF_DLLI) || (dmaObj->size != dataSize))
        return -1; /* data size mismatch */

    return 0;
}
