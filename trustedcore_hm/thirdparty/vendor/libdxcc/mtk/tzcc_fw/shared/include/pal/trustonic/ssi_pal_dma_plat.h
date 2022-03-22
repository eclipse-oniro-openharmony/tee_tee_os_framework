/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_DMA_PLAT_H
#define _SSI_PAL_DMA_PLAT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief   stub function, the function should initialize the DMA mapping of the platform (if needed)
 *
 * @param[in] buffSize - buffer size in Bytes
 * @param[in] physBuffAddr - physical start address of the memory to map
 *
 * @return Virtual start address of contiguous memory
 */
extern uint32_t SaSi_PalDmaInit(uint32_t buffSize, uint32_t physBuffAddr);

/*
 * @brief   free system resources created in PD_PAL_DmaInit()
 *
 *
 * @return void
 */
extern void SaSi_PalDmaTerminate(void);
#ifdef __cplusplus
}
#endif

#endif
