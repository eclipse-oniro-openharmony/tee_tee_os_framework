/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef __DMA_BUFFER_PLAT_H__
#define __DMA_BUFFER_PLAT_H__

/* Host pointer is always "smart pointer" hence, no manipulation has
   to be made but compiling to an empty macro */
#define IS_SMART_PTR(ptr)             (0)
#define PTR_TO_DMA_BUFFER(ptr)        ((DmaBuffer_s *)(ptr))
#define DMA_BUFFER_TO_PTR(pDmaBuffer) ((void *)(pDmaBuffer))
#endif /* __DMA_BUFFER_PLAT_H__ */
