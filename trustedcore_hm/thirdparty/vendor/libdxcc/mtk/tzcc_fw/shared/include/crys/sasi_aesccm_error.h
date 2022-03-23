/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_AESCCM_ERROR_H
#define SaSi_AESCCM_ERROR_H

#include "sasi_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* !
@file
@brief This module contains the definitions of the SaSi AESCCM errors.
*/

/* *********************** Defines **************************** */

/* The SaSi AESCCM module errors.
   SaSi_AESCCM_MODULE_ERROR_BASE = 0x00F01500 */
#define SaSi_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR   (SaSi_AESCCM_MODULE_ERROR_BASE + 0x00UL)
#define SaSi_AESCCM_ILLEGAL_KEY_SIZE_ERROR               (SaSi_AESCCM_MODULE_ERROR_BASE + 0x01UL)
#define SaSi_AESCCM_INVALID_KEY_POINTER_ERROR            (SaSi_AESCCM_MODULE_ERROR_BASE + 0x02UL)
#define SaSi_AESCCM_INVALID_ENCRYPT_MODE_ERROR           (SaSi_AESCCM_MODULE_ERROR_BASE + 0x03UL)
#define SaSi_AESCCM_USER_CONTEXT_CORRUPTED_ERROR         (SaSi_AESCCM_MODULE_ERROR_BASE + 0x04UL)
#define SaSi_AESCCM_DATA_IN_POINTER_INVALID_ERROR        (SaSi_AESCCM_MODULE_ERROR_BASE + 0x05UL)
#define SaSi_AESCCM_DATA_OUT_POINTER_INVALID_ERROR       (SaSi_AESCCM_MODULE_ERROR_BASE + 0x06UL)
#define SaSi_AESCCM_DATA_IN_SIZE_ILLEGAL                 (SaSi_AESCCM_MODULE_ERROR_BASE + 0x07UL)
#define SaSi_AESCCM_DATA_OUT_DATA_IN_OVERLAP_ERROR       (SaSi_AESCCM_MODULE_ERROR_BASE + 0x08UL)
#define SaSi_AESCCM_DATA_OUT_SIZE_INVALID_ERROR          (SaSi_AESCCM_MODULE_ERROR_BASE + 0x09UL)
#define SaSi_AESCCM_ADDITIONAL_BLOCK_NOT_PERMITTED_ERROR (SaSi_AESCCM_MODULE_ERROR_BASE + 0x0AUL)
#define SaSi_AESCCM_ILLEGAL_DMA_BUFF_TYPE_ERROR          (SaSi_AESCCM_MODULE_ERROR_BASE + 0x0BUL)
#define SaSi_AESCCM_ILLEGAL_PARAMETER_SIZE_ERROR         (SaSi_AESCCM_MODULE_ERROR_BASE + 0x0CUL)
#define SaSi_AESCCM_ILLEGAL_PARAMETER_PTR_ERROR          (SaSi_AESCCM_MODULE_ERROR_BASE + 0x0DUL)
#define SaSi_AESCCM_ILLEGAL_DATA_TYPE_ERROR              (SaSi_AESCCM_MODULE_ERROR_BASE + 0x0EUL)
#define SaSi_AESCCM_CCM_MAC_INVALID_ERROR                (SaSi_AESCCM_MODULE_ERROR_BASE + 0x0FUL)
#define SaSi_AESCCM_LAST_BLOCK_NOT_PERMITTED_ERROR       (SaSi_AESCCM_MODULE_ERROR_BASE + 0x10UL)
#define SaSi_AESCCM_ILLEGAL_PARAMETER_ERROR              (SaSi_AESCCM_MODULE_ERROR_BASE + 0x11UL)
#define SaSi_AESCCM_NOT_ALL_ADATA_WAS_PROCESSED_ERROR    (SaSi_AESCCM_MODULE_ERROR_BASE + 0x13UL)
#define SaSi_AESCCM_NOT_ALL_DATA_WAS_PROCESSED_ERROR     (SaSi_AESCCM_MODULE_ERROR_BASE + 0x14UL)
#define SaSi_AESCCM_ADATA_WAS_PROCESSED_ERROR            (SaSi_AESCCM_MODULE_ERROR_BASE + 0x15UL)
#define SaSi_AESCCM_ILLEGAL_NONCE_SIZE_ERROR             (SaSi_AESCCM_MODULE_ERROR_BASE + 0x16UL)
#define SaSi_AESCCM_ILLEGAL_TAG_SIZE_ERROR               (SaSi_AESCCM_MODULE_ERROR_BASE + 0x17UL)

#define SaSi_AESCCM_CTX_SIZES_ERROR      (SaSi_AESCCM_MODULE_ERROR_BASE + 0x28UL)
#define SaSi_AESCCM_ILLEGAL_PARAMS_ERROR (SaSi_AESCCM_MODULE_ERROR_BASE + 0x29UL)
#define SaSi_AESCCM_IS_NOT_SUPPORTED     (SaSi_AESCCM_MODULE_ERROR_BASE + 0xFFUL)

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  *************************** */

/* *********************** Public Variables ******************* */

/* *********************** Public Functions ******************* */

#ifdef __cplusplus
}
#endif

#endif
