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

#ifndef _DX_PAL_PLAT_H
#define _DX_PAL_PLAT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief   stub function, the function should initialize the DMA mapping of the platform (if needed)
 *
 * @param[in] buffSize - buffer size in Bytes
 *
 * @return Virtual start address of contiguous memory
 */
uint32_t dx_pal_dma_init(uint32_t buffSize);

/*
 * @brief   free system resources created in PD_PAL_DmaInit()
 *
 *
 * @return void
 */
extern void DX_PAL_DmaTerminate();
#ifdef __cplusplus
}
#endif

#endif
