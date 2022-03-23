/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_UTIL_DEFS_H
#define _SSI_UTIL_DEFS_H

/* !
@file
@brief This file contains CryptoCell Util general definitions.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "ssi_pal_types_plat.h"
#include "ssi_util_key_derivation_defs.h"

/* *****************************************************************************
 *                            DEFINITIONS
 * *************************************************************************** */

#define SASI_UTIL_AES_128BIT_SIZE 16 // same as SEP_AES_128_BIT_KEY_SIZE
/* ************************************** */
/* CMAC derive key definitions */
/* ************************************** */
#define SASI_UTIL_CMAC_DERV_MIN_DATA_IN_SIZE    SASI_UTIL_FIX_DATA_MIN_SIZE_IN_BYTES + 2
#define SASI_UTIL_CMAC_DERV_MAX_DATA_IN_SIZE    SASI_UTIL_MAX_KDF_SIZE_IN_BYTES
#define SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES 0x10UL
#define SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_WORDS (SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES / 4)

/* ! Util Error type. */
typedef uint32_t SaSiUtilError_t;
/* ! Defines the CMAC result buffer  - 16 bytes array. */
typedef uint8_t SaSiUtilAesCmacResult_t[SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES];

#ifdef __cplusplus
}
#endif

#endif /* _SSI_UTIL_DEFS_H */
