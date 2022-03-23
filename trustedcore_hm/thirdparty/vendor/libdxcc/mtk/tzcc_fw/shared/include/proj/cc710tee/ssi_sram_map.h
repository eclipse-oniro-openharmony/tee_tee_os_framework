/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_SRAM_MAP_H_
#define _SSI_SRAM_MAP_H_

/* !
@file
@brief This file contains internal SRAM mapping definitions.
*/

#ifdef __cplusplus
extern "C" {
#endif

#define SASI_SRAM_PKA_BASE_ADDRESS   0x0
#define SASI_PKA_SRAM_SIZE_IN_KBYTES 6

#define SASI_SRAM_RND_HW_DMA_ADDRESS 0x1800
#define SASI_SRAM_RND_MAX_SIZE       0x800 /* !< Addresses 6K-8K in SRAM reserved for RND operations. */

#define SASI_SRAM_MLLI_BASE_ADDR 0x2000
#define SASI_SRAM_MLLI_MAX_SIZE  0x800 /* !< Addresses 8K-10K in SRAM reserved for MLLI tables. */

#define SASI_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_ADDR           0x3C00
#define SASI_SRAM_DRIVER_ADAPTOR_CONTEXT_CACHE_LAST_WORD_ADDR 0x3FFC
#define SASI_SRAM_DRIVER_ADAPTOR_CONTEXT_MAX_SIZE \
    0x400 /* !< Last 1K, addresses 15K-16K, in SRAM reserved for driver adaptor context. */

#define SASI_SRAM_MAX_SIZE 0x4000 /* !< SRAM total size is 16KB.  */

#ifdef __cplusplus
}
#endif

#endif /* _SSI_SRAM_MAP_H_ */
