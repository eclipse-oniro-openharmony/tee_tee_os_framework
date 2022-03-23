/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_DES_ERROR_H
#define SaSi_DES_ERROR_H

#include "sasi_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* !
@file
@brief This module contains the definitions of the SaSi DES errors.
*/

/* *********************** Defines **************************** */

/* The SaSi DES module errors */
#define SaSi_DES_INVALID_USER_CONTEXT_POINTER_ERROR   (SaSi_DES_MODULE_ERROR_BASE + 0x0UL)
#define SaSi_DES_INVALID_IV_PTR_ON_NON_ECB_MODE_ERROR (SaSi_DES_MODULE_ERROR_BASE + 0x1UL)
#define SaSi_DES_ILLEGAL_OPERATION_MODE_ERROR         (SaSi_DES_MODULE_ERROR_BASE + 0x2UL)
#define SaSi_DES_ILLEGAL_NUM_OF_KEYS_ERROR            (SaSi_DES_MODULE_ERROR_BASE + 0x3UL)
#define SaSi_DES_INVALID_KEY_POINTER_ERROR            (SaSi_DES_MODULE_ERROR_BASE + 0x4UL)
#define SaSi_DES_INVALID_ENCRYPT_MODE_ERROR           (SaSi_DES_MODULE_ERROR_BASE + 0x5UL)
#define SaSi_DES_USER_CONTEXT_CORRUPTED_ERROR         (SaSi_DES_MODULE_ERROR_BASE + 0x6UL)
#define SaSi_DES_DATA_IN_POINTER_INVALID_ERROR        (SaSi_DES_MODULE_ERROR_BASE + 0x7UL)
#define SaSi_DES_DATA_OUT_POINTER_INVALID_ERROR       (SaSi_DES_MODULE_ERROR_BASE + 0x8UL)
#define SaSi_DES_DATA_SIZE_ILLEGAL                    (SaSi_DES_MODULE_ERROR_BASE + 0x9UL)
#define SaSi_DES_DATA_OUT_DATA_IN_OVERLAP_ERROR       (SaSi_DES_MODULE_ERROR_BASE + 0xAUL)
#define SaSi_DES_ILLEGAL_PARAMS_ERROR                 (SaSi_DES_MODULE_ERROR_BASE + 0x13UL)

#define SaSi_DES_IS_NOT_SUPPORTED (SaSi_DES_MODULE_ERROR_BASE + 0x1FUL)

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

#ifdef __cplusplus
}
#endif

#endif
