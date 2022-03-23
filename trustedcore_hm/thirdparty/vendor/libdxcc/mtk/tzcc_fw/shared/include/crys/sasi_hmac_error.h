/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_HMAC_ERROR_H
#define SaSi_HMAC_ERROR_H

#include "sasi_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ! @file
 *  @brief This module contains the definitions of the SaSi HMAC errors.
 *
 */

/* *********************** Defines **************************** */

/* The SaSi HASH module errors */
#define SaSi_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR  (SaSi_HMAC_MODULE_ERROR_BASE + 0x0UL)
#define SaSi_HMAC_ILLEGAL_OPERATION_MODE_ERROR        (SaSi_HMAC_MODULE_ERROR_BASE + 0x1UL)
#define SaSi_HMAC_USER_CONTEXT_CORRUPTED_ERROR        (SaSi_HMAC_MODULE_ERROR_BASE + 0x2UL)
#define SaSi_HMAC_DATA_IN_POINTER_INVALID_ERROR       (SaSi_HMAC_MODULE_ERROR_BASE + 0x3UL)
#define SaSi_HMAC_DATA_SIZE_ILLEGAL                   (SaSi_HMAC_MODULE_ERROR_BASE + 0x4UL)
#define SaSi_HMAC_INVALID_RESULT_BUFFER_POINTER_ERROR (SaSi_HMAC_MODULE_ERROR_BASE + 0x5UL)
#define SaSi_HMAC_INVALID_KEY_POINTER_ERROR           (SaSi_HMAC_MODULE_ERROR_BASE + 0x6UL)
#define SaSi_HMAC_UNVALID_KEY_SIZE_ERROR              (SaSi_HMAC_MODULE_ERROR_BASE + 0x7UL)
#define SaSi_HMAC_LAST_BLOCK_ALREADY_PROCESSED_ERROR  (SaSi_HMAC_MODULE_ERROR_BASE + 0xBUL)
#define SaSi_HMAC_ILLEGAL_PARAMS_ERROR                (SaSi_HMAC_MODULE_ERROR_BASE + 0xCUL)

#define SaSi_HMAC_CTX_SIZES_ERROR (SaSi_HMAC_MODULE_ERROR_BASE + 0xEUL)

#define SaSi_HMAC_IS_NOT_SUPPORTED (SaSi_HMAC_MODULE_ERROR_BASE + 0xFUL)

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

#ifdef __cplusplus
}
#endif

#endif
