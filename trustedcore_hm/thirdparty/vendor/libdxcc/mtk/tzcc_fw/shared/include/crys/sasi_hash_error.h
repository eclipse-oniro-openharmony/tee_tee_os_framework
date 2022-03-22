/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_HASH_ERROR_H
#define SaSi_HASH_ERROR_H

#include "sasi_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* !
@file
@brief This module contains the definitions of the SaSi HASH errors.
*/

/* *********************** Defines **************************** */
/* HASH module on the SaSi layer base address - 0x00F00200 */
/* The SaSi HASH module errors */
#define SaSi_HASH_INVALID_USER_CONTEXT_POINTER_ERROR  (SaSi_HASH_MODULE_ERROR_BASE + 0x0UL)
#define SaSi_HASH_ILLEGAL_OPERATION_MODE_ERROR        (SaSi_HASH_MODULE_ERROR_BASE + 0x1UL)
#define SaSi_HASH_USER_CONTEXT_CORRUPTED_ERROR        (SaSi_HASH_MODULE_ERROR_BASE + 0x2UL)
#define SaSi_HASH_DATA_IN_POINTER_INVALID_ERROR       (SaSi_HASH_MODULE_ERROR_BASE + 0x3UL)
#define SaSi_HASH_DATA_SIZE_ILLEGAL                   (SaSi_HASH_MODULE_ERROR_BASE + 0x4UL)
#define SaSi_HASH_INVALID_RESULT_BUFFER_POINTER_ERROR (SaSi_HASH_MODULE_ERROR_BASE + 0x5UL)
#define SaSi_HASH_DATA_SIZE_IS_ILLEGAL_FOR_CSI_ERROR  (SaSi_HASH_MODULE_ERROR_BASE + 0x8UL)
#define SaSi_HASH_LAST_BLOCK_ALREADY_PROCESSED_ERROR  (SaSi_HASH_MODULE_ERROR_BASE + 0xCUL)
#define SaSi_HASH_ILLEGAL_PARAMS_ERROR                (SaSi_HASH_MODULE_ERROR_BASE + 0xDUL)

#define SaSi_HASH_CTX_SIZES_ERROR (SaSi_HASH_MODULE_ERROR_BASE + 0xEUL)

#define SaSi_HASH_IS_NOT_SUPPORTED (SaSi_HASH_MODULE_ERROR_BASE + 0xFUL)

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

#ifdef __cplusplus
}
#endif

#endif
