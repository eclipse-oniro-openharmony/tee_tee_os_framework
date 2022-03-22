/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SEP_BYPASS_H
#define SEP_BYPASS_H

#include "ssi_crypto_ctx.h"
#include "dma_buffer.h"

/* *****************************************************************************
 *                TYPE DEFINITIONS
 * *************************************************************************** */
typedef enum BypassType { BYPASS_SRAM = 0, BYPASS_DLLI = 1, BYPASS_MLLI = 2, BYPASS_MAX = INT32_MAX } Bypass_t;

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */

/* !
 * Memory copy using HW engines
 *
 *  reserved [unused]
 *  pDmaInputBuffer [in] -A structure which represents the DMA input buffer.
 *  pDmaOutputBuffer [in/out] -A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in ssi_error.h.
 */
int ProcessBypass(struct drv_ctx_generic *reserved, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

#endif /* BYPASS_H */
