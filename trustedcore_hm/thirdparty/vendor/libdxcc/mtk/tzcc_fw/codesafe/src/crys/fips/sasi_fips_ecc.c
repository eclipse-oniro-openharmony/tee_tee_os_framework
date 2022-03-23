/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#include "ssi_pal_log.h"
#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "sasi_rnd.h"
#include "sasi_ecpki_types.h"
#include "sasi_ecpki_build.h"
#include "sasi_ecpki_domain.h"
#include "sasi_ecpki_local.h"
#include "sasi_ecpki_dh.h"
#include "sasi_ecpki_ecdsa.h"
#include "sasi_fips.h"
#include "sasi_fips_error.h"
#include "sasi_fips_defs.h"
#include "sasi_fips_ecc_defs.h"
#include "sasi_fips_ecdsa_kat_data.h"
#include "sasi_fips_ecdh_kat_data.h"
#include "sasi_common.h"

#define FIPS_ECC_DOMAIN_TYPE SaSi_ECPKI_DomainID_secp256r1

#define FIPS_ECC_HASH_MODE        SaSi_ECPKI_AFTER_HASH_SHA256_mode
#define FIPS_ECC_SIGNED_DATA_SIZE (2 * SaSi_ECPKI_ORDER_MAX_LENGTH_IN_WORDS * SASI_32BIT_WORD_SIZE)

typedef uint8_t FipsEccSignedData_t[FIPS_ECC_SIGNED_DATA_SIZE];

static const uint8_t eccFipsDataIn[SaSi_HASH_SHA256_DIGEST_SIZE_IN_BYTES] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

/* Conditional test for ECC.  Use SECP-256R1 curve */
SaSiError_t SaSi_FipsEccConditionalTest(SaSi_RND_Context_t *pRndContext, SaSi_ECPKI_UserPrivKey_t *pUserPrivKey,
                                        SaSi_ECPKI_UserPublKey_t *pUserPublKey, SaSi_ECPKI_KG_FipsContext_t *pFipsCtx)
{
    SaSiError_t rc           = SaSi_OK;
    CC_FipsError_t fipsRc    = CC_TEE_FIPS_ERROR_GENERAL;
    uint32_t dataSignOutSize = sizeof(FipsEccSignedData_t);
    SaSi_ECDSA_SignUserContext_t *pSignUserContext;
    SaSi_ECDSA_VerifyUserContext_t *pVerifyUserContext;
    FipsEccSignedData_t *pDataSignOut;

    CHECK_AND_RETURN_UPON_FIPS_STATE();

    if (pFipsCtx == NULL) {
        rc = SaSi_FIPS_ERROR;
        goto End;
    }
    if ((pRndContext == NULL) || (pUserPrivKey == NULL) || (pUserPublKey == NULL)) {
        rc = SaSi_FIPS_ERROR;
        goto End;
    }

    pDataSignOut     = (FipsEccSignedData_t *)pFipsCtx->signBuff;
    pSignUserContext = &(pFipsCtx->operationCtx.signCtx);

    // Generate signature
    rc = SaSi_ECDSA_Sign_MTK(pRndContext, pSignUserContext, pUserPrivKey, FIPS_ECC_HASH_MODE, (uint8_t *)eccFipsDataIn,
                             sizeof(eccFipsDataIn), (uint8_t *)pDataSignOut, &dataSignOutSize);
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_COND;
        goto End;
    }

    // Verify signature data is diffenet than the input
    rc = SaSi_PalMemCmp(eccFipsDataIn, pDataSignOut, sizeof(eccFipsDataIn));
    if (rc == SaSi_OK) {
        rc     = 1; // from dx update patch
        fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_COND;
        goto End;
    }

    SaSi_PalMemSetZero(pSignUserContext, sizeof(SaSi_ECDSA_SignUserContext_t));
    pVerifyUserContext = (SaSi_ECDSA_VerifyUserContext_t *)(&pFipsCtx->operationCtx.verifyCtx);

    // Verify the signature
    rc = SaSi_ECDSA_Verify_MTK(pVerifyUserContext, pUserPublKey, FIPS_ECC_HASH_MODE, (uint8_t *)pDataSignOut,
                               dataSignOutSize, (uint8_t *)eccFipsDataIn, sizeof(eccFipsDataIn));
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDSA_VERIFY_COND;
        goto End;
    }
    FipsSetTrace(CC_FIPS_TRACE_ECC_COND);

End:
    if (rc != SaSi_OK) {
        FipsSetError(fipsRc);
        return SaSi_FIPS_ERROR;
    }
    return rc;

} /* END OF SaSi_FipsEccConditionalTest */

/* KAT test for ECC. Use SECP-256R1 curve */
CC_FipsError_t SaSi_FipsEcdsaKat(SaSi_RND_Context_t *pRndContext, SaSi_ECDSAFipsKatContext_t *pFipsCtx)
{
    SaSiError_t rc;
    CC_FipsError_t fipsRc = CC_TEE_FIPS_ERROR_OK;
    SaSi_ECPKI_UserPublKey_t *pUserPublKey;
    SaSi_ECPKI_UserPrivKey_t *pUserPrivKey;
    SaSi_ECPKI_BUILD_TempData_t *pTempBuff;
    SaSi_ECDSA_SignUserContext_t *pSignUserContext;
    SaSi_ECDSA_VerifyUserContext_t *pVerifyUserContext;
    uint8_t *pDataSignOut;
    uint32_t dataSignOutSize;
    uint32_t ephemeralKey[SaSi_ECPKI_FIPS_ORDER_LENGTH / SASI_32BIT_WORD_SIZE];

    if ((pRndContext == NULL) || (pFipsCtx == NULL)) {
        return CC_TEE_FIPS_ERROR_GENERAL;
    }

    pUserPrivKey     = &pFipsCtx->keyContextData.userSignData.PrivKey;
    pSignUserContext = &pFipsCtx->keyContextData.userSignData.signCtx;
    pDataSignOut     = pFipsCtx->signBuff;
    dataSignOutSize  = sizeof(pFipsCtx->signBuff);

    // Build ptivate key for sign opeartion
    rc = SaSi_ECPKI_BuildPrivKey_MTK(SaSi_ECPKI_GetEcDomain(FIPS_ECC_DOMAIN_TYPE), (uint8_t *)fipsEcdsaR256r1KatPrivKey,
                                     sizeof(fipsEcdsaR256r1KatPrivKey), pUserPrivKey);
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT;
        goto End;
    }

    rc = SaSi_COMMON_ReverseMemcpy((uint8_t *)ephemeralKey, (uint8_t *)fipsEcdsaR256r1KatEphemeralKey,
                                   sizeof(fipsEcdsaR256r1KatEphemeralKey));
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT;
        goto End;
    }

    // Use non-integrated sign operation to be able to use ephemeral key
    rc = SaSi_ECDSA_SignInit_MTK(pSignUserContext, pUserPrivKey, SaSi_ECPKI_HASH_SHA256_mode);
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT;
        goto End;
    }

    rc = SaSi_ECDSA_SignUpdate_MTK(pSignUserContext, (uint8_t *)fipsEcdsaR256r1KatDataIn,
                                   sizeof(fipsEcdsaR256r1KatDataIn));
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT;
        goto End;
    }

    rc = _DX_ECDSA_SignFinish_MTK(pSignUserContext, pRndContext, (uint8_t *)pDataSignOut, &dataSignOutSize, 0,
                                  ephemeralKey);
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT;
        goto End;
    }

    // Verify signature is teh same as expected
    rc = SaSi_PalMemCmp((uint8_t *)fipsEcdsaR256r1KatSignature, pDataSignOut, sizeof(fipsEcdsaR256r1KatSignature));
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDSA_SIGN_PUT;
        goto End;
    }

    SaSi_PalMemSetZero((uint8_t *)&pFipsCtx->keyContextData, sizeof(pFipsCtx->keyContextData));
    pUserPublKey       = &pFipsCtx->keyContextData.userVerifyData.PublKey;
    pTempBuff          = &pFipsCtx->keyContextData.userVerifyData.buildOrVerify.tempData;
    pVerifyUserContext = &pFipsCtx->keyContextData.userVerifyData.buildOrVerify.verifyCtx;

    // Build public key for verify operation
    rc = SaSi_ECPKI_BuildPublKeyFullCheck(SaSi_ECPKI_GetEcDomain(FIPS_ECC_DOMAIN_TYPE),
                                          (uint8_t *)fipsEcdsaR256r1KatPubKey, sizeof(fipsEcdsaR256r1KatPubKey),
                                          pUserPublKey, pTempBuff);
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDSA_VERIFY_PUT;
        goto End;
    }

    // Verify the signature
    rc = SaSi_ECDSA_Verify_MTK(pVerifyUserContext, pUserPublKey, SaSi_ECPKI_HASH_SHA256_mode, (uint8_t *)pDataSignOut,
                               dataSignOutSize, (uint8_t *)fipsEcdsaR256r1KatDataIn, sizeof(fipsEcdsaR256r1KatDataIn));
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDSA_VERIFY_PUT;
        goto End;
    }

    FipsSetTrace(CC_FIPS_TRACE_ECDSA_PUT);

End:
    SaSi_PalMemSetZero(pRndContext, sizeof(SaSi_RND_Context_t));
    SaSi_PalMemSetZero(pFipsCtx, sizeof(SaSi_ECDSAFipsKatContext_t));

    return fipsRc;
}

/* KAT test for ECDH.  */
CC_FipsError_t SaSi_FipsEcdhKat(SaSi_ECDHFipsKatContext_t *pFipsCtx)
{
    SaSiError_t rc;
    CC_FipsError_t fipsRc = CC_TEE_FIPS_ERROR_OK;
    SaSi_ECPKI_UserPublKey_t *pPartnerPublKey;
    SaSi_ECPKI_UserPrivKey_t *pUserPrivKey;
    SaSi_ECDH_TempData_t *pEcdhTempBuff;
    SaSi_ECPKI_BUILD_TempData_t *pEcpkiTempBuff;
    uint8_t *pSecretBuff;
    uint32_t secretBuffSize;

    if (pFipsCtx == NULL) {
        return CC_TEE_FIPS_ERROR_ECDH_PUT;
    }

    pPartnerPublKey = &pFipsCtx->pubKey;
    pUserPrivKey    = &pFipsCtx->privKey;
    pEcdhTempBuff   = &pFipsCtx->tmpData.ecdhTempBuff;
    pEcpkiTempBuff  = &pFipsCtx->tmpData.ecpkiTempData;
    pSecretBuff     = pFipsCtx->secretBuff;
    secretBuffSize  = sizeof(pFipsCtx->secretBuff);

    // Build other pertner Public key
    rc = SaSi_ECPKI_BuildPublKeyFullCheck(SaSi_ECPKI_GetEcDomain(FIPS_ECC_DOMAIN_TYPE),
                                          (uint8_t *)fipsEcdhR256r1KatPartnerPubKey,
                                          sizeof(fipsEcdhR256r1KatPartnerPubKey), pPartnerPublKey, pEcpkiTempBuff);
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDH_PUT;
        goto End;
    }

    // Build user private key
    rc = SaSi_ECPKI_BuildPrivKey_MTK(SaSi_ECPKI_GetEcDomain(FIPS_ECC_DOMAIN_TYPE),
                                     (uint8_t *)fipsEcdhR256r1KatUserPrivKey, sizeof(fipsEcdhR256r1KatUserPrivKey),
                                     pUserPrivKey);
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDH_PUT;
        goto End;
    }

    // Generate teh secrete
    rc = SaSi_ECDH_SVDP_DH_MTK(pPartnerPublKey, pUserPrivKey, pSecretBuff, &secretBuffSize, pEcdhTempBuff);
    if ((rc != SaSi_OK) || (secretBuffSize != sizeof(pFipsCtx->secretBuff))) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDH_PUT;
        goto End;
    }

    // Verify secret is the same as expected
    rc = SaSi_PalMemCmp((uint8_t *)fipsEcdhR256r1KatSecret, pSecretBuff, secretBuffSize);
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_ECDH_PUT;
        goto End;
    }

    FipsSetTrace(CC_FIPS_TRACE_ECDH_PUT);

End:
    SaSi_PalMemSetZero(pFipsCtx, sizeof(SaSi_ECDHFipsKatContext_t));
    return fipsRc;
}
