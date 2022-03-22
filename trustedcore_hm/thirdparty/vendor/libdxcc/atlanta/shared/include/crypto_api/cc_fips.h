/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/

#ifndef _CC_FIPS_H_
#define _CC_FIPS_H_

#include "cc_pal_types.h"
#include "cc_rsa_types.h"
#include "cc_ecpki_types.h"
#include "cc_dh.h"

/*!
@file
@brief This file contains definitions and APIs that are used in the CryptoCell FIPS module.
*/

typedef uint32_t CCFipsState_t;

#define CC_FIPS_STATE_NOT_SUPPORTED     0x0
#define CC_FIPS_STATE_ERROR             0x1
#define CC_FIPS_STATE_SUPPORTED         0x2
#define CC_FIPS_STATE_SUSPENDED         0x4
#define CC_FIPS_STATE_CRYPTO_APPROVED   0x8

typedef enum CCFipsError {
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
} CCFipsError_t;

typedef enum CCFipsReeStatus {
        CC_TEE_FIPS_REE_STATUS_OK = 0,
        CC_TEE_FIPS_REE_STATUS_ERROR,
        CC_TEE_FIPS_REE_STATUS_RESERVE32B = INT32_MAX
} CCFipsReeStatus_t;

typedef enum CCFipsCryptoUsageState {
        CC_TEE_FIPS_CRYPTO_USAGE_STATE_NON_APPROVED = 0,
        CC_TEE_FIPS_CRYPTO_USAGE_STATE_APPROVED,
        CC_TEE_FIPS_CRYPTO_USAGE_STATE_RESERVE32B = INT32_MAX
} CCFipsCryptoUsageState_t;

typedef union{
	CCRsaFipsKatContext_t	fipsRsaCtx;
	CCEcdsaFipsKatContext_t	fipsEcdsaCtx;
	CCDhFipsKat_t		fipsDhCtx;
	CCEcdhFipsKatContext_t	fipsEcdhCtx;
        CCPrngFipsKatCtx_t           fipsPrngCtx;
}CCFipsKatContext_t;


#define CC_FIPS_CRYPTO_USAGE_SET_APPROVED() \
        CC_FipsCryptoUsageStateSet(CC_TEE_FIPS_CRYPTO_USAGE_STATE_APPROVED)
#define CC_FIPS_CRYPTO_USAGE_SET_NON_APPROVED() \
        CC_FipsCryptoUsageStateSet(CC_TEE_FIPS_CRYPTO_USAGE_STATE_NON_APPROVED)

/*!
@brief This function is used to get the current fips error of the ARM TrustZone CryptoCell TEE library.

@return CC_OK on success,
@return A non-zero value from cc_fips_error.h on failure.
*/
CCError_t CC_FipsErrorGet(
                CCFipsError_t *pFipsError  /*!< [out] The current fips error of the library. */
);


/*!
@brief This function is used to get the current fips state (FIPS certification state set to ON or OFF) and zeroization state
of the ARM TrustZone CryptoCell TEE library.

@return CC_OK on success,
@return A non-zero value from cc_fips_error.h on failure.
*/
CCError_t CC_FipsStateGet(CCFipsState_t  *pFipsState, /*!< [out] The fips State of the library. */
			  bool  *pIsDeviceZeroized     /*!< [out] Is device was zeroized. */);

/*!
@brief This function is used to set the permission (approved/non-approved) of the crypto operations in the suspended state
of the ARM TrustZone CryptoCell TEE library.

@return CC_OK on success,
@return A non-zero value from cc_fips_error.h on failure.
*/
CCError_t CC_FipsCryptoUsageStateSet(
                CCFipsCryptoUsageState_t state  /*!< [in]  The state of the crypto operations. */
);

/*!
@brief This function is used to handle the Interrupt that is issued when the CC712 REE is updating its FIPS status.

\note This function should be integarted into the Interrupt Handler Routine of the user's operating system.
      In the example implementation it is called through a PAL API - CC_PalFipsWaitForReeStatus.

@return CC_OK on success,
@return A non-zero value from cc_fips_error.h on failure.
*/
CCError_t CC_FipsIrqHandle(void);

#endif  // _CC_FIPS_H_
