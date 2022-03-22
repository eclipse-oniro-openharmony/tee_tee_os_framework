/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_UTIL_KEY_DERIVATION_H
#define _SSI_UTIL_KEY_DERIVATION_H

/* !
@file
@brief This module defines the API that supports Key derivation function as specified
       in [SP800-108] in section "KDF in Counter Mode".
*/

#ifdef __cplusplus
extern "C" {
#endif

#include "ssi_util_defs.h"
#include "ssi_util_key_derivation_defs.h"
#include "ssi_aes.h"

/* *****************************************************************************
 *                            DEFINITIONS
 * *************************************************************************** */

/* !
key derivation type
*/
typedef enum {
    SASI_UTIL_USER_KEY        = 0,
    SASI_UTIL_ROOT_KEY        = 1,
    SASI_UTIL_END_OF_KEY_TYPE = 0x7FFFFFFF
} SaSiUtilKeyType_t;

/* !
@brief  The key derivation function is as specified in [SP800-108] in section "KDF in Counter Mode".
    The derivation is based on length l, label L, context C and derivation key Ki.
    AES-CMAC is used as the pseudorandom function (PRF).

@return SASI_UTIL_OK on success.
@return A non-zero value from ssi_util_error.h on failure.
*/

/*    A key derivation functions can iterates n times until l bits of keying material are generated.
        For each of the iteration of the PRF, i=1 to n, do:
          result(0) = 0;
        K(i) = PRF (Ki, [i] || Label || 0x00 || Context || length);
        results(i) = result(i-1) || K(i);

        concisely, result(i) = K(i) || k(i-1) || .... || k(0) */
SaSiUtilError_t SaSi_UtilKeyDerivation(
    SaSiUtilKeyType_t keyType,      /* !< [in] The key type that is used as an input to a key derivation function.
                       Can be one of: SASI_UTIL_USER_KEY or SASI_UTIL_ROOT_KEY. */
    SaSiAesUserKeyData_t *pUserKey, /* !< [in] A pointer to the user's key buffer (in case of SASI_UTIL_USER_KEY). */
    const uint8_t *pLabel,          /* !< [in] A string that identifies the purpose for the derived keying material. */
    size_t labelSize,               /* !< [in] The label size should be in range of 1 to 64 bytes length. */
    const uint8_t
        *pContextData,  /* !< [in] A binary string containing the information related to the derived keying material. */
    size_t contextSize, /* !< [in] The context size should be in range of 1 to 64 bytes length. */
    uint8_t *pDerivedKey, /* !< [out] Keying material output (MUST be atleast the size of derivedKeySize). */
    size_t derivedKeySize /* !< [in] Size of the derived keying material in bytes (limited to 4080 bytes). */
);

#ifdef __cplusplus
}
#endif

#endif /* _SSI_UTIL_KEY_DERIVATION_H */
