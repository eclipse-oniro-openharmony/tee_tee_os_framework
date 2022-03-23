/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_UTIL_RPMB_H
#define _SSI_UTIL_RPMB_H

/* !
@file
@brief This file contains the functions and definitions for the RPMB.
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "ssi_util_defs.h"
#include "ssi_util_error.h"

/* *****************************************************************************
 *                            DEFINITIONS
 * *************************************************************************** */

/* **************************************** */
/*   RPMB shared secret key definitions    */
/* **************************************** */

#define SASI_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES    284
#define SASI_UTIL_MIN_RPMB_DATA_BUFFERS            1
#define SASI_UTIL_MAX_RPMB_DATA_BUFFERS            65535
#define SASI_UTIL_HMAC_SHA256_DIGEST_SIZE_IN_WORDS 8

typedef uint8_t SaSiUtilRpmbKey_t[SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES * 2];
typedef uint8_t SaSiUtilRpmbDataBuffer_t[SASI_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES];
typedef uint32_t SaSiUtilHmacResult_t[SASI_UTIL_HMAC_SHA256_DIGEST_SIZE_IN_WORDS];

/*
 * @brief This function derives a 256-bit RPMB key by performing AES CMAC on fixed data, using KDR. Because the
 * derivation is performed based on fixed data, the key does not need to be saved, and can be derived again
 * consistently.
 *
 *
 * @return SASI_UTIL_OK on success.
 * @return A non-zero value on failure as defined in ssi_util_error.h.
 */
SaSiUtilError_t
SaSi_UtilDeriveRPMBKey(SaSiUtilRpmbKey_t pRpmbKey /* !< [out] Pointer to 32byte output, to be used as RPMB key. */);

/*
 * @brief This function computes HMAC SHA-256 authentication code of a sequence of 284 Byte RPMB frames
 *      (as defined in [JESD84]), using the RPMB key (which is derived internally using ::SaSi_UtilDeriveRPMBKey).
 *
 *
 * @return SASI_UTIL_OK on success.
 * @return A non-zero value on failure as defined in ssi_util_error.h.
 */
SaSiUtilError_t SaSi_UtilSignRPMBFrames(
    unsigned long
        *pListOfDataFrames, /* !< [in] Pointer to a list of 284 Byte frame addresses. The entire frame list is signed. */
    uint32_t listSize,      /* !< [in] The number of 284 Byte frames in the list, up to 65,535. */
    SaSiUtilHmacResult_t pHmacResult /* !< [out] Pointer to the output data (HMAC result). */);

#ifdef __cplusplus
}
#endif

#endif /* _SSI_UTIL_RPMB_H */
