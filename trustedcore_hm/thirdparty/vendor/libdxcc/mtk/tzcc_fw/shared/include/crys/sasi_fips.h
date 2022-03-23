/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SaSi_FIPS_H_
#define _SaSi_FIPS_H_

#include "ssi_pal_types.h"
#include "sasi_rsa_types.h"
#include "sasi_ecpki_types.h"
#include "sasi_dh.h"

/* !
@file
@brief This file contains definitions and APIs that are used in the SaSi FIPS module.
In case FIPS certification mode is enabled, it is expected from the user to connect the FIPS errors that comes from the
REE to the TEE and vice versa. To update the TEE with FIPS error from the REE the user must call
::SaSi_FIPS_SetReeStatus.
*/

typedef uint32_t CC_FipsState_t;

#define CC_FIPS_STATE_NOT_SUPPORTED   0x0
#define CC_FIPS_STATE_ERROR           0x1
#define CC_FIPS_STATE_SUPPORTED       0x2
#define CC_FIPS_STATE_SUSPENDED       0x4
#define CC_FIPS_STATE_CRYPTO_APPROVED 0x8

typedef enum CC_FipsError {
    CC_TEE_FIPS_ERROR_OK = 0,
    CC_TEE_FIPS_ERROR_GENERAL,
    CC_TEE_FIPS_ERROR_FROM_REE,
    CC_TEE_FIPS_ERROR_AES_ECB_PUT,
    CC_TEE_FIPS_ERROR_AES_CBC_PUT,
    CC_TEE_FIPS_ERROR_AES_OFB_PUT,
    CC_TEE_FIPS_ERROR_AES_CTR_PUT,
    CC_TEE_FIPS_ERROR_AES_CBC_CTS_PUT,
    CC_TEE_FIPS_ERROR_AES_CBC_MAC_PUT,
    CC_TEE_FIPS_ERROR_AES_CMAC_PUT,
    CC_TEE_FIPS_ERROR_AESCCM_PUT,
    CC_TEE_FIPS_ERROR_AES_XTS_PUT,
    CC_TEE_FIPS_ERROR_DES_ECB_PUT,
    CC_TEE_FIPS_ERROR_DES_CBC_PUT,
    CC_TEE_FIPS_ERROR_SHA1_PUT,
    CC_TEE_FIPS_ERROR_SHA256_PUT,
    CC_TEE_FIPS_ERROR_SHA512_PUT,
    CC_TEE_FIPS_ERROR_HMAC_SHA256_PUT,
    CC_TEE_FIPS_ERROR_RSA_ENC_PUT,
    CC_TEE_FIPS_ERROR_RSA_DEC_PUT,
    CC_TEE_FIPS_ERROR_RSA_SIGN_PUT,
    CC_TEE_FIPS_ERROR_RSA_VERIFY_PUT,
    CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT,
    CC_TEE_FIPS_ERROR_ECDSA_VERIFY_PUT,
    CC_TEE_FIPS_ERROR_DH_PUT,
    CC_TEE_FIPS_ERROR_ECDH_PUT,
    CC_TEE_FIPS_ERROR_PRNG_PUT,
    CC_TEE_FIPS_ERROR_RSA_ENC_COND,
    CC_TEE_FIPS_ERROR_RSA_DEC_COND,
    CC_TEE_FIPS_ERROR_ECDSA_SIGN_COND,
    CC_TEE_FIPS_ERROR_ECDSA_VERIFY_COND,
    CC_TEE_FIPS_ERROR_PRNG_CONT,
    CC_TEE_FIPS_ERROR_RESERVE32B = INT32_MAX
} CC_FipsError_t;

typedef enum CC_FipsReeStatus {
    CC_TEE_FIPS_REE_STATUS_OK = 0,
    CC_TEE_FIPS_REE_STATUS_ERROR,
    CC_TEE_FIPS_REE_STATUS_RESERVE32B = INT32_MAX
} CC_FipsReeStatus_t;

typedef enum CC_FipsCryptoUsageState {
    CC_TEE_FIPS_CRYPTO_USAGE_STATE_NON_APPROVED = 0,
    CC_TEE_FIPS_CRYPTO_USAGE_STATE_APPROVED,
    CC_TEE_FIPS_CRYPTO_USAGE_STATE_RESERVE32B = INT32_MAX
} CC_FipsCryptoUsageState_t;

typedef union {
    SaSi_RSAFipsKatContext_t fipsRsaCtx;
    SaSi_ECDSAFipsKatContext_t fipsEcdsaCtx;
    SaSi_DH_FipsKat_t fipsDhCtx;
    SaSi_ECDHFipsKatContext_t fipsEcdhCtx;
    SaSi_PrngFipsKatCtx_t fipsPrngCtx;
} SaSi_FipsKatContext_t;

#define SaSi_FIPS_CRYPTO_USAGE_SET_APPROVED() SaSi_FIPS_SetCryptoUsageState(CC_TEE_FIPS_CRYPTO_USAGE_STATE_APPROVED)
#define SaSi_FIPS_CRYPTO_USAGE_SET_NON_APPROVED() \
    SaSi_FIPS_SetCryptoUsageState(CC_TEE_FIPS_CRYPTO_USAGE_STATE_NON_APPROVED)

/* !
@brief This function is used to set a FIPS error that comes from the ARM TrustZone CryptoCell REE driver
to the ARM TrustZone CryptoCell TEE library.

@return SASI_OK on success,
@return A non-zero value from sasi_fips_error.h on failure.
*/
SaSiError_t SaSi_FIPS_SetReeStatus(CC_FipsReeStatus_t status /* !< [in]  The current ree fips status. */
);

/* !
@brief This function is used to get the current fips error of the ARM TrustZone CryptoCell TEE library.

@return SASI_OK on success,
@return A non-zero value from sasi_fips_error.h on failure.
*/
SaSiError_t SaSi_FIPS_GetError(CC_FipsError_t *pFipsError /* !< [out] The current fips error of the library. */
);

/* !
@brief This function is used to get the current fips state (FIPS certification state set to ON or OFF) and zeroization
state of the ARM TrustZone CryptoCell TEE library.

@return SASI_OK on success,
@return A non-zero value from sasi_fips_error.h on failure.
*/
SaSiError_t SaSi_FIPS_GetState(CC_FipsState_t *pFipsState, /* !< [out] The fips State of the library. */
                               bool *pIsDeviceZeroized /* !< [out] Is device was zeroized. */);

/* !
@brief This function is used to set the permission (approved/non-approved) of the crypto operations in the suspended
state of the ARM TrustZone CryptoCell TEE library.

@return SASI_OK on success,
@return A non-zero value from sasi_fips_error.h on failure.
*/
SaSiError_t
SaSi_FIPS_SetCryptoUsageState(CC_FipsCryptoUsageState_t state /* !< [in]  The state of the crypto operations. */
);

#endif // _SaSi_FIPS_H_
