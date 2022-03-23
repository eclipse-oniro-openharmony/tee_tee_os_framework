/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_KDF_ERROR_H
#define SaSi_KDF_ERROR_H

#include "sasi_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* !
@file
@brief This module contains the definitions of the SaSi KDF errors.
 */

/* *********************** Defines ***************************** */

/* The SaSi KDF module errors / base address - 0x00F01100 */
#define SaSi_KDF_INVALID_ARGUMENT_POINTER_ERROR         (SaSi_KDF_MODULE_ERROR_BASE + 0x0UL)
#define SaSi_KDF_INVALID_ARGUMENT_SIZE_ERROR            (SaSi_KDF_MODULE_ERROR_BASE + 0x1UL)
#define SaSi_KDF_INVALID_ARGUMENT_OPERATION_MODE_ERROR  (SaSi_KDF_MODULE_ERROR_BASE + 0x2UL)
#define SaSi_KDF_INVALID_ARGUMENT_HASH_MODE_ERROR       (SaSi_KDF_MODULE_ERROR_BASE + 0x3UL)
#define SaSi_KDF_INVALID_KEY_DERIVATION_MODE_ERROR      (SaSi_KDF_MODULE_ERROR_BASE + 0x4UL)
#define SaSi_KDF_INVALID_SHARED_SECRET_VALUE_SIZE_ERROR (SaSi_KDF_MODULE_ERROR_BASE + 0x5UL)
#define SaSi_KDF_INVALID_OTHER_INFO_SIZE_ERROR          (SaSi_KDF_MODULE_ERROR_BASE + 0x6UL)
#define SaSi_KDF_INVALID_KEYING_DATA_SIZE_ERROR         (SaSi_KDF_MODULE_ERROR_BASE + 0x7UL)
#define SaSi_KDF_INVALID_ALGORITHM_ID_POINTER_ERROR     (SaSi_KDF_MODULE_ERROR_BASE + 0x8UL)
#define SaSi_KDF_INVALID_ALGORITHM_ID_SIZE_ERROR        (SaSi_KDF_MODULE_ERROR_BASE + 0x9UL)

#define SaSi_KDF_HOST_MSG_GENERAL_RPC_A_ERROR (SaSi_KDF_MODULE_ERROR_BASE + 0xAUL)
#define SaSi_KDF_HOST_MSG_GENERAL_RPC_B_ERROR (SaSi_KDF_MODULE_ERROR_BASE + 0xBUL)
#define SaSi_KDF_HOST_MSG_GENERAL_RPC_C_ERROR (SaSi_KDF_MODULE_ERROR_BASE + 0xCUL)

#define SaSi_KDF_IS_NOT_SUPPORTED (SaSi_KDF_MODULE_ERROR_BASE + 0xFFUL)

/* *********************** Enums ******************************* */

/* *********************** Typedefs  *************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

#ifdef __cplusplus
}
#endif

#endif
