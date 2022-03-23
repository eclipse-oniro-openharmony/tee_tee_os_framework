/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_RND_ERROR_H
#define SaSi_RND_ERROR_H

#include "sasi_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* !
@file
@brief This module contains the definitions of the SaSi RND errors.
*/

/* *********************** Defines **************************** */
/* RND module on the SaSi layer base address - 0x00F00C00 */

#define SaSi_RND_DATA_OUT_POINTER_INVALID_ERROR          (SaSi_RND_MODULE_ERROR_BASE + 0x0UL)
#define SaSi_RND_CAN_NOT_GENERATE_RAND_IN_RANGE          (SaSi_RND_MODULE_ERROR_BASE + 0x1UL)
#define SaSi_RND_CPRNG_TEST_FAIL_ERROR                   (SaSi_RND_MODULE_ERROR_BASE + 0x2UL)
#define SaSi_RND_ADDITIONAL_INPUT_BUFFER_NULL            (SaSi_RND_MODULE_ERROR_BASE + 0x3UL)
#define SaSi_RND_ADDITIONAL_INPUT_SIZE_ERROR             (SaSi_RND_MODULE_ERROR_BASE + 0x4UL)
#define SaSi_RND_DATA_SIZE_OVERFLOW_ERROR                (SaSi_RND_MODULE_ERROR_BASE + 0x5UL)
#define SaSi_RND_VECTOR_SIZE_ERROR                       (SaSi_RND_MODULE_ERROR_BASE + 0x6UL)
#define SaSi_RND_RESEED_COUNTER_OVERFLOW_ERROR           (SaSi_RND_MODULE_ERROR_BASE + 0x7UL)
#define SaSi_RND_INSTANTIATION_NOT_DONE_ERROR            (SaSi_RND_MODULE_ERROR_BASE + 0x8UL)
#define SaSi_RND_TRNG_LOSS_SAMPLES_ERROR                 (SaSi_RND_MODULE_ERROR_BASE + 0x9UL)
#define SaSi_RND_TRNG_TIME_EXCEED_ERROR                  (SaSi_RND_MODULE_ERROR_BASE + 0xAUL)
#define SaSi_RND_TRNG_LOSS_SAMPLES_AND_TIME_EXCEED_ERROR (SaSi_RND_MODULE_ERROR_BASE + 0xBUL)
#define SaSi_RND_IS_KAT_MODE_ERROR                       (SaSi_RND_MODULE_ERROR_BASE + 0xCUL)
#define SaSi_RND_OPERATION_IS_NOT_SUPPORTED_ERROR        (SaSi_RND_MODULE_ERROR_BASE + 0xDUL)
#define SaSi_RND_STATE_VALIDATION_TAG_ERROR              (SaSi_RND_MODULE_ERROR_BASE + 0xEUL)

#define SaSi_RND_IS_NOT_SUPPORTED (SaSi_RND_MODULE_ERROR_BASE + 0xFUL)

#define SaSi_RND_GEN_A_ERROR                            (SaSi_RND_MODULE_ERROR_BASE + 0x10UL)
#define SaSi_RND_GEN_B_ERROR                            (SaSi_RND_MODULE_ERROR_BASE + 0x11UL)
#define SaSi_RND_GEN_C_ERROR                            (SaSi_RND_MODULE_ERROR_BASE + 0x12UL)
#define SaSi_RND_ILLEGAL_PARAMS_ACCORDING_TO_PRIV_ERROR (SaSi_RND_MODULE_ERROR_BASE + 0x13UL)
#define SaSi_RND_GEN_VECTOR_FUNC_ERROR                  (SaSi_RND_MODULE_ERROR_BASE + 0x14UL)

#define SaSi_RND_WORK_BUFFER_PTR_INVALID_ERROR (SaSi_RND_MODULE_ERROR_BASE + 0x20UL)
#define SaSi_RND_ILLEGAL_AES_KEY_SIZE_ERROR    (SaSi_RND_MODULE_ERROR_BASE + 0x21UL)
#define SaSi_RND_ILLEGAL_DATA_PTR_ERROR        (SaSi_RND_MODULE_ERROR_BASE + 0x22UL)
#define SaSi_RND_ILLEGAL_DATA_SIZE_ERROR       (SaSi_RND_MODULE_ERROR_BASE + 0x23UL)
#define SaSi_RND_ILLEGAL_PARAMETER_ERROR       (SaSi_RND_MODULE_ERROR_BASE + 0x24UL)
#define SaSi_RND_STATE_PTR_INVALID_ERROR       (SaSi_RND_MODULE_ERROR_BASE + 0x25UL)
#define SaSi_RND_TRNG_ERRORS_ERROR             (SaSi_RND_MODULE_ERROR_BASE + 0x26UL)
#define SaSi_RND_CONTEXT_PTR_INVALID_ERROR     (SaSi_RND_MODULE_ERROR_BASE + 0x27UL)

#define SaSi_RND_VECTOR_OUT_PTR_ERROR          (SaSi_RND_MODULE_ERROR_BASE + 0x30UL)
#define SaSi_RND_VECTOR_OUT_SIZE_ERROR         (SaSi_RND_MODULE_ERROR_BASE + 0x31UL)
#define SaSi_RND_MAX_VECTOR_IS_TOO_SMALL_ERROR (SaSi_RND_MODULE_ERROR_BASE + 0x32UL)
#define SaSi_RND_KAT_DATA_PARAMS_ERROR         (SaSi_RND_MODULE_ERROR_BASE + 0x33UL)
#define SaSi_RND_TRNG_KAT_NOT_SUPPORTED_ERROR  (SaSi_RND_MODULE_ERROR_BASE + 0x34UL)
#define SaSi_RND_SRAM_NOT_SUPPORTED_ERROR      (SaSi_RND_MODULE_ERROR_BASE + 0x35UL)

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

#ifdef __cplusplus
}
#endif

#endif
