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

#ifndef  SEP_BYPASS_H
#define  SEP_BYPASS_H

#include "cc_crypto_ctx.h"
#include "dma_buffer.h"

/******************************************************************************
*				TYPE DEFINITIONS
******************************************************************************/
typedef enum BypassType {
	BYPASS_SRAM	= 0,
	BYPASS_DLLI	= 1,
	BYPASS_MLLI	= 2,
	BYPASS_MAX	= INT32_MAX
} Bypass_t;

/******************************************************************************
*				FUNCTION PROTOTYPES
******************************************************************************/

/*!
 * Memory copy using HW engines
 *
 *  reserved [unused]
 *  pDmaInputBuffer [in] -A structure which represents the DMA input buffer.
 *  pDmaOutputBuffer [in/out] -A structure which represents the DMA output buffer.
 *
 * \return int One of DX_SYM_* error codes defined in cc_sym_error.h.
 */
int ProcessBypass(uint32_t *reserved, uint32_t *pCtx_reserved, DmaBuffer_s *pDmaInputBuffer, DmaBuffer_s *pDmaOutputBuffer);

#endif /*BYPASS_H*/

