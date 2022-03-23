/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_DH_ERROR_H
#define SaSi_DH_ERROR_H

#include "sasi_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* !
@file
@brief This file contains error codes definitions for SaSi DH module.
*/
/* *********************** Defines **************************** */
/* DH module on the SaSi layer base address - 0x00F00500 */
/* The SaSi DH module errors */
#define SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR        (SaSi_DH_MODULE_ERROR_BASE + 0x0UL)
#define SaSi_DH_INVALID_ARGUMENT_SIZE_ERROR           (SaSi_DH_MODULE_ERROR_BASE + 0x1UL)
#define SaSi_DH_INVALID_ARGUMENT_OPERATION_MODE_ERROR (SaSi_DH_MODULE_ERROR_BASE + 0x2UL)
#define SaSi_DH_INVALID_ARGUMENT_HASH_MODE_ERROR      (SaSi_DH_MODULE_ERROR_BASE + 0x3UL)

/* the derived secret key size needed is wrong */
#define SaSi_DH_SECRET_KEYING_DATA_SIZE_ILLEGAL_ERROR       (SaSi_DH_MODULE_ERROR_BASE + 0x4UL)
#define SaSi_DH_INVALID_L_ARGUMENT_ERROR                    (SaSi_DH_MODULE_ERROR_BASE + 0x5UL)
#define SaSi_DH_ARGUMENT_PRIME_SMALLER_THAN_GENERATOR_ERROR (SaSi_DH_MODULE_ERROR_BASE + 0x6UL)
#define SaSi_DH_ARGUMENT_GENERATOR_SMALLER_THAN_ZERO_ERROR  (SaSi_DH_MODULE_ERROR_BASE + 0x7UL)
#define SaSi_DH_ARGUMENT_PRV_SIZE_ERROR                     (SaSi_DH_MODULE_ERROR_BASE + 0x8UL)
#define SaSi_DH_ARGUMENT_BUFFER_SIZE_ERROR                  (SaSi_DH_MODULE_ERROR_BASE + 0x9UL)
#define SaSi_DH_INVALID_SHARED_SECRET_VALUE_ERROR           (SaSi_DH_MODULE_ERROR_BASE + 0xAUL)
#define SaSi_DH_IS_NOT_SUPPORTED                            (SaSi_DH_MODULE_ERROR_BASE + 0xFUL)

#define SaSi_DH_X942_HYBRID_SIZE1_BUFFER_ERROR (SaSi_DH_MODULE_ERROR_BASE + 0x15UL)

/* The requested derived secret key size is invalid */
#define SaSi_DH_SECRET_KEY_SIZE_NEEDED_ERROR (SaSi_DH_MODULE_ERROR_BASE + 0x16UL)
#define SaSi_DH_SECRET_KEY_SIZE_OUTPUT_ERROR (SaSi_DH_MODULE_ERROR_BASE + 0x17UL)
#define SaSi_DH_OTHERINFO_SIZE_ERROR         (SaSi_DH_MODULE_ERROR_BASE + 0x18UL)

/* DH domain and key generation and checking errors */
#define SaSi_DH_INVALID_MODULUS_SIZE_ERROR          (SaSi_DH_MODULE_ERROR_BASE + 0x20UL)
#define SaSi_DH_INVALID_ORDER_SIZE_ERROR            (SaSi_DH_MODULE_ERROR_BASE + 0x21UL)
#define SaSi_DH_INVALID_SEED_SIZE_ERROR             (SaSi_DH_MODULE_ERROR_BASE + 0x22UL)
#define SaSi_DH_INVALID_J_FACTOR_PTR_OR_SIZE_ERROR  (SaSi_DH_MODULE_ERROR_BASE + 0x23UL)
#define SaSi_DH_INVALID_GENERATOR_PTR_OR_SIZE_ERROR (SaSi_DH_MODULE_ERROR_BASE + 0x24UL)

#define SaSi_DH_CHECK_DOMAIN_PRIMES_NOT_VALID_ERROR         (SaSi_DH_MODULE_ERROR_BASE + 0x25UL)
#define SaSi_DH_CHECK_DOMAIN_GENERATOR_NOT_VALID_ERROR      (SaSi_DH_MODULE_ERROR_BASE + 0x26UL)
#define SaSi_DH_INVALID_PUBLIC_KEY_SIZE_ERROR               (SaSi_DH_MODULE_ERROR_BASE + 0x27UL)
#define SaSi_DH_CHECK_PUB_KEY_NOT_VALID_ERROR               (SaSi_DH_MODULE_ERROR_BASE + 0x28UL)
#define SaSi_DH_CHECK_GENERATOR_SIZE_OR_PTR_NOT_VALID_ERROR (SaSi_DH_MODULE_ERROR_BASE + 0x29UL)
#define SaSi_DH_CHECK_SEED_SIZE_OR_PTR_NOT_VALID_ERROR      (SaSi_DH_MODULE_ERROR_BASE + 0x2AUL)
#define SaSi_DH_CHECK_GENERATOR_NOT_VALID_ERROR             (SaSi_DH_MODULE_ERROR_BASE + 0x2BUL)
#define SaSi_DH_PRIME_P_GENERATION_FAILURE_ERROR            (SaSi_DH_MODULE_ERROR_BASE + 0x2CUL)
#define SaSi_DH_INVALID_PUBLIC_KEY_ERROR                    (SaSi_DH_MODULE_ERROR_BASE + 0x2DUL)
#define SaSi_DH_PASSED_INVALID_SEED_ERROR                   (SaSi_DH_MODULE_ERROR_BASE + 0x2EUL)

#define SaSi_DH_HOST_MSG_GENERAL_RPC_A_ERROR (SaSi_DH_MODULE_ERROR_BASE + 0x30UL)
#define SaSi_DH_HOST_MSG_GENERAL_RPC_B_ERROR (SaSi_DH_MODULE_ERROR_BASE + 0x31UL)
#define SaSi_DH_HOST_MSG_GENERAL_RPC_C_ERROR (SaSi_DH_MODULE_ERROR_BASE + 0x32UL)

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

#ifdef __cplusplus
}
#endif

#endif
