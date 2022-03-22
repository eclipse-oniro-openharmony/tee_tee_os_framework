/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_COMMON_ERROR_H
#define SaSi_COMMON_ERROR_H

#include "sasi_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */

/* SaSi COMMON module errors. Base address - 0x00F00D00 */

#define SaSi_COMMON_INIT_HW_SEM_CREATION_FAILURE   (SaSi_COMMON_MODULE_ERROR_BASE + 0x0UL)
#define SaSi_COMMON_DATA_IN_POINTER_INVALID_ERROR  (SaSi_COMMON_MODULE_ERROR_BASE + 0x4UL)
#define SaSi_COMMON_DATA_SIZE_ILLEGAL              (SaSi_COMMON_MODULE_ERROR_BASE + 0x5UL)
#define SaSi_COMMON_DATA_OUT_DATA_IN_OVERLAP_ERROR (SaSi_COMMON_MODULE_ERROR_BASE + 0x6UL)
#define SaSi_COMMON_DATA_OUT_POINTER_INVALID_ERROR (SaSi_COMMON_MODULE_ERROR_BASE + 0x7UL)
#define SaSi_COMMON_OUTPUT_BUFF_SIZE_ILLEGAL       (SaSi_COMMON_MODULE_ERROR_BASE + 0x9UL)

#define SaSi_COMMON_TST_UTIL_CHUNK_SIZE_SMALL_ERROR (SaSi_COMMON_MODULE_ERROR_BASE + 0x10UL)
#define SaSi_COMMON_ERROR_IN_SAVING_LLI_DATA_ERROR  (SaSi_COMMON_MODULE_ERROR_BASE + 0x11UL)

#define SaSi_COMMON_TST_UTIL_LLI_ENTRY_SIZE_TOO_SMALL_ERROR (SaSi_COMMON_MODULE_ERROR_BASE + 0x12UL)
#define SaSi_COMMON_TST_CSI_DATA_SIZE_EXCEED_ERROR          (SaSi_COMMON_MODULE_ERROR_BASE + 0x13UL)
#define SaSi_COMMON_TST_CSI_MODULE_ID_OUT_OF_RANGE          (SaSi_COMMON_MODULE_ERROR_BASE + 0x14UL)
#define SaSi_COMMON_TST_CSI_MEMORY_MAPPING_ERROR            (SaSi_COMMON_MODULE_ERROR_BASE + 0x15UL)

#define SaSi_COMMON_TERM_HW_SEM_DELETE_FAILURE (SaSi_COMMON_MODULE_ERROR_BASE + 0x16UL)

#define SaSi_COMMON_TST_UTIL_NOT_INTEGER_CHAR_ERROR (SaSi_COMMON_MODULE_ERROR_BASE + 0x17UL)
#define SaSi_COMMON_TST_UTIL_BUFFER_IS_SMALL_ERROR  (SaSi_COMMON_MODULE_ERROR_BASE + 0x18UL)
#define SaSi_COMMON_POINTER_NOT_ALIGNED_ERROR       (SaSi_COMMON_MODULE_ERROR_BASE + 0x19UL)

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

#ifdef __cplusplus
}
#endif

#endif
