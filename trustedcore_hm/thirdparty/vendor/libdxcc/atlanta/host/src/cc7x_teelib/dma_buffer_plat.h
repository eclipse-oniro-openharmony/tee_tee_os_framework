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

#ifndef __DMA_BUFFER_PLAT_H__
#define __DMA_BUFFER_PLAT_H__

/* Host pointer is always "smart pointer" hence, no manipulation has
   to be made but compiling to an empty macro */
#define IS_SMART_PTR(ptr) (0)
#define PTR_TO_DMA_BUFFER(ptr) ((DmaBuffer_s *)(ptr))
#define DMA_BUFFER_TO_PTR(pDmaBuffer) ((void *)(pDmaBuffer))
#endif /*__DMA_BUFFER_PLAT_H__*/
