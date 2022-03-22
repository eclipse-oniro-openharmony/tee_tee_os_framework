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

#ifndef SEP_BYPASS_H
#define SEP_BYPASS_H

#include "sep_ctx.h"
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
 * \return int One of DX_SYM_* error codes defined in dx_error.h.
 */
int ProcessBypass(struct sep_ctx_generic *reserved, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

#endif /* BYPASS_H */
