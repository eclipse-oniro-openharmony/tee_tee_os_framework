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

#ifndef __DMA_BUFFER_PLAT_H__
#define __DMA_BUFFER_PLAT_H__

/* Host pointer is always "smart pointer" hence, no manipulation has
   to be made but compiling to an empty macro */
#define IS_SMART_PTR(ptr)             (0)
#define PTR_TO_DMA_BUFFER(ptr)        ((DmaBuffer_s *)(ptr))
#define DMA_BUFFER_TO_PTR(pDmaBuffer) ((void *)(pDmaBuffer))
#endif /* __DMA_BUFFER_PLAT_H__ */
