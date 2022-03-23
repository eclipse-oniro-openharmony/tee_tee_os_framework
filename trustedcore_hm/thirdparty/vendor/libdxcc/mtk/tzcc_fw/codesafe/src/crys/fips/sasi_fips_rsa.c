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
#include "sasi_rsa_types.h"
#include "sasi_rsa_build.h"
#include "sasi_rsa_schemes.h"
#include "sasi_fips.h"
#include "sasi_fips_error.h"
#include "sasi_fips_defs.h"
#include "sasi_fips_rsa_defs.h"
#include "sasi_fips_rsa_kat_data.h"

#define RSA_KAT_RND_STATE_ENCRYPTION 1
#define RSA_KAT_RND_STATE_SIGNATURE  2

// taken the smaller hash digest, after hash is not supported
#define FIPS_RSA_HASH_TYPE SaSi_RSA_HASH_SHA1_mode
// for scheme 2.1, dataIn size must be smaller than modulus size (minimum 512 bits) minus 2*hashDigest minuns 2
// this leads to 64-2*20-2 = 22 bytes of data in size; same size as SaSi_RSAKGFipsContext_t->decBuff
#define FIPS_RSA_DATA_SIZE                                             \
    ((SaSi_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS / SASI_BITS_IN_BYTE) - \
     2 * (SaSi_HASH_SHA1_DIGEST_SIZE_IN_BYTES)-2) // total of 22

typedef uint8_t FipsRsaDecrypedData_t[FIPS_RSA_DATA_SIZE];
typedef uint8_t FipsRsaEncrypedData_t[SaSi_RSA_MAX_KEY_GENERATION_HW_SIZE_BITS / SASI_BITS_IN_BYTE];

// input data for RSA conditional test - randomaly chossen
static const uint8_t rsaFipsDataIn[FIPS_RSA_DATA_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                                           0x10, 0x01, 0x02, 0x03, 0x04, 0x05 };

// The function performs RSA KAT encrypt & decrypt test according to test vectors
static CC_FipsError_t fipsRsaKatEncryptTest(SaSi_RND_Context_t *pRndContext, SaSi_RSAFipsKatContext_t *pFipsCtx)
{
    uint32_t rc = CC_TEE_FIPS_ERROR_OK;
    SaSi_RSAUserPubKey_t *pUserPubKey;
    SaSi_RSAUserPrivKey_t *pUserPrivKey;
    SaSi_RSAPrimeData_t *pPrimeData;
    uint8_t *pDataOutEnc;
    uint8_t *pDataOutDec;
    uint32_t outDataSize;

    if ((pRndContext == NULL) || (pFipsCtx == NULL)) {
        return CC_TEE_FIPS_ERROR_GENERAL;
    }

    pUserPubKey  = &pFipsCtx->userKey.userPubKey;
    pUserPrivKey = &pFipsCtx->userKey.userPrivKey;
    pPrimeData   = &pFipsCtx->userContext.primData;
    pDataOutDec  = pFipsCtx->userData.userOaepData.decBuff;
    pDataOutEnc  = pFipsCtx->userData.userOaepData.encBuff;

    // Build public key for encryption
    rc = SaSi_RSA_Build_PubKey_MTK(pUserPubKey, (uint8_t *)fipsRsaOaepKatPubExponent, sizeof(fipsRsaOaepKatPubExponent),
                                   (uint8_t *)fipsRsaOaepKat2048Modulus, sizeof(fipsRsaOaepKat2048Modulus));
    if (rc != SaSi_OK) {
        return CC_TEE_FIPS_ERROR_RSA_ENC_PUT;
    }

    // Encrypt known data
    pRndContext->rndState.StateFlag = RSA_KAT_RND_STATE_ENCRYPTION;
    rc = SaSi_RSA_OAEP_Encrypt(pRndContext, pUserPubKey, pPrimeData, FIPS_RSA_HASH_TYPE, NULL, 0, SaSi_PKCS1_MGF1,
                               (uint8_t *)fipsRsaOaepKatDataIn, sizeof(fipsRsaOaepKatDataIn), pDataOutEnc);
    if (rc != SaSi_OK) {
        return CC_TEE_FIPS_ERROR_RSA_ENC_PUT;
    }

    // Verify encrypted data is as expected
    rc = SaSi_PalMemCmp((uint8_t *)fipsRsaOaepKat2048ExpEncryption, pDataOutEnc,
                        sizeof(fipsRsaOaepKat2048ExpEncryption));
    if (rc != SaSi_OK) {
        return CC_TEE_FIPS_ERROR_RSA_ENC_PUT;
    }

    // Build private key for decrypt
    rc = SaSi_RSA_Build_PrivKey_MTK(pUserPrivKey, (uint8_t *)fipsRsaOaepKat2048PrivExpD,
                                    sizeof(fipsRsaOaepKat2048PrivExpD), (uint8_t *)fipsRsaOaepKatPubExponent,
                                    sizeof(fipsRsaOaepKatPubExponent), (uint8_t *)fipsRsaOaepKat2048Modulus,
                                    sizeof(fipsRsaOaepKat2048Modulus));
    if (rc != SaSi_OK) {
        return CC_TEE_FIPS_ERROR_RSA_DEC_PUT;
    }

    // Decrypt the encrypted data
    outDataSize = sizeof(fipsRsaOaepKatDataIn);
    rc = SaSi_RSA_OAEP_Decrypt(pUserPrivKey, pPrimeData, FIPS_RSA_HASH_TYPE, NULL, 0, SaSi_PKCS1_MGF1, pDataOutEnc,
                               sizeof(fipsRsaOaepKat2048Modulus), pDataOutDec, (uint16_t *)&outDataSize);
    if (rc != SaSi_OK) {
        return CC_TEE_FIPS_ERROR_RSA_DEC_PUT;
    }

    // Verify decrypted data equals to input
    rc = SaSi_PalMemCmp(fipsRsaOaepKatDataIn, pDataOutDec, sizeof(fipsRsaOaepKatDataIn));
    if (rc != SaSi_OK) {
        return CC_TEE_FIPS_ERROR_RSA_DEC_PUT;
    }

    return CC_TEE_FIPS_ERROR_OK;
}

// The function performs RSA KAT sign & verify test according to test vectors
static CC_FipsError_t fipsRsaKatSignTest(SaSi_RND_Context_t *pRndContext, SaSi_RSAFipsKatContext_t *pFipsCtx)
{
    uint32_t rc = CC_TEE_FIPS_ERROR_OK;
    SaSi_RSAUserPubKey_t *pUserPubKey;
    SaSi_RSAUserPrivKey_t *pUserPrivKey;
    SaSi_RSAPrivUserContext_t *pUserPrivContext;
    SaSi_RSAPubUserContext_t *pUserPubContext;
    uint8_t *pDataOutSign;
    uint32_t outDataSize;

    if ((pRndContext == NULL) || (pFipsCtx == NULL)) {
        return CC_TEE_FIPS_ERROR_GENERAL;
    }

    pUserPubKey      = &pFipsCtx->userKey.userPubKey;
    pUserPrivKey     = &pFipsCtx->userKey.userPrivKey;
    pDataOutSign     = pFipsCtx->userData.signBuff;
    pUserPrivContext = &pFipsCtx->userContext.userPrivContext;
    pUserPubContext  = &pFipsCtx->userContext.userPubContext;
    SaSi_PalMemSetZero(pDataOutSign, sizeof(pFipsCtx->userData.signBuff));
    outDataSize = sizeof(pFipsCtx->userData.signBuff);

    pRndContext->rndState.StateFlag = RSA_KAT_RND_STATE_SIGNATURE;

    // Build private key for sign operation
    rc = SaSi_RSA_Build_PrivKey_MTK(pUserPrivKey, (uint8_t *)fipsRsaPssKat2048PrivExponent,
                                    sizeof(fipsRsaPssKat2048PrivExponent), (uint8_t *)fipsRsaPssKatPubExponent,
                                    sizeof(fipsRsaPssKatPubExponent), (uint8_t *)fipsRsaPssKat2048Modulus,
                                    sizeof(fipsRsaPssKat2048Modulus));
    if (rc != SaSi_OK) {
        return CC_TEE_FIPS_ERROR_RSA_SIGN_PUT;
    }
    // Calculate signature
    rc = SaSi_RSA_PSS_Sign(pRndContext, pUserPrivContext, pUserPrivKey, FIPS_RSA_HASH_TYPE, SaSi_PKCS1_MGF1,
                           sizeof(fipsRsaPssKatSalt), (uint8_t *)fipsRsaPssKatDataIn, sizeof(fipsRsaPssKatDataIn),
                           pDataOutSign, (uint16_t *)&outDataSize);
    if (rc != SaSi_OK) {
        return CC_TEE_FIPS_ERROR_RSA_SIGN_PUT;
    }

    // Verify signature data is as expected
    rc = SaSi_PalMemCmp(fipsRsaPssKat2048ExpSignature, pDataOutSign, sizeof(fipsRsaPssKat2048ExpSignature));
    if (rc != SaSi_OK) {
        return CC_TEE_FIPS_ERROR_RSA_SIGN_PUT;
    }

    // Build private key for verify operation
    rc = SaSi_RSA_Build_PubKey_MTK(pUserPubKey, (uint8_t *)fipsRsaPssKatPubExponent, sizeof(fipsRsaPssKatPubExponent),
                                   (uint8_t *)fipsRsaPssKat2048Modulus, sizeof(fipsRsaPssKat2048Modulus));
    if (rc != SaSi_OK) {
        return CC_TEE_FIPS_ERROR_RSA_VERIFY_PUT;
    }

    // Verify signature
    rc = SaSi_RSA_PSS_Verify(pUserPubContext, pUserPubKey, FIPS_RSA_HASH_TYPE, SaSi_PKCS1_MGF1,
                             sizeof(fipsRsaPssKatSalt), (uint8_t *)fipsRsaPssKatDataIn, sizeof(fipsRsaPssKatDataIn),
                             pDataOutSign);
    if (rc != SaSi_OK) {
        return CC_TEE_FIPS_ERROR_RSA_VERIFY_PUT;
    }

    return CC_TEE_FIPS_ERROR_OK;
}

// The function is being called twice: once for encrypt and the second for sign
// the return vector is according to state flag
CEXPORT_C SaSiError_t fipsRsaKatGenVector(SaSi_RND_State_t *rndState_ptr, uint16_t outSizeBytes, /* in */
                                          uint8_t *out_ptr)                                      /* out */
{
    if ((rndState_ptr == NULL) || (out_ptr == NULL)) {
        return SaSi_FIPS_ERROR;
    }

    if (rndState_ptr->StateFlag == RSA_KAT_RND_STATE_ENCRYPTION) {
        if (outSizeBytes < sizeof(fipsRsaOaepKatSeed)) {
            return SaSi_FIPS_ERROR;
        }
        SaSi_PalMemCopy(out_ptr, fipsRsaOaepKatSeed, sizeof(fipsRsaOaepKatSeed));
        return SaSi_OK;
    }
    if (rndState_ptr->StateFlag == RSA_KAT_RND_STATE_SIGNATURE) {
        if (outSizeBytes < sizeof(fipsRsaPssKatSalt)) {
            return SaSi_FIPS_ERROR;
        }
        SaSi_PalMemCopy(out_ptr, fipsRsaPssKatSalt, sizeof(fipsRsaPssKatSalt));
        return SaSi_OK;
    }
    return SaSi_FIPS_ERROR;
}

/* Conditional test for RSA. Use PKCS 2.1 for encrypt and decrypt */
SaSiError_t SaSi_FipsRsaConditionalTest(SaSi_RND_Context_t *pRndContext, SaSi_RSAUserPrivKey_t *pCcUserPrivKey,
                                        SaSi_RSAUserPubKey_t *pCcUserPubKey, SaSi_RSAKGFipsContext_t *pFipsCtx)
{
    /* the error identifier */
    SaSiError_t rc        = SaSi_OK;
    CC_FipsError_t fipsRc = CC_TEE_FIPS_ERROR_GENERAL;
    uint32_t keySizeInBytes;
    uint16_t decDataSize;
    SaSi_RSAPrimeData_t *pPrimeData;
    FipsRsaDecrypedData_t *pDataDecOut;
    FipsRsaEncrypedData_t *pDataEncOut;

    CHECK_AND_RETURN_UPON_FIPS_STATE();

    /* ...... checking the key database handle pointer .................... */
    if (pFipsCtx == NULL) {
        rc = SaSi_FIPS_ERROR;
        goto End;
    }
    if ((pRndContext == NULL) || (pCcUserPrivKey == NULL) || (pCcUserPubKey == NULL)) {
        rc = SaSi_FIPS_ERROR;
        goto End;
    }

    pPrimeData  = &(pFipsCtx->primData);
    pDataDecOut = (FipsRsaDecrypedData_t *)pFipsCtx->decBuff;
    pDataEncOut = (FipsRsaEncrypedData_t *)pFipsCtx->encBuff;

    keySizeInBytes = ((((SaSiRSAPubKey_t *)(pCcUserPubKey->PublicKeyDbBuff))->nSizeInBits) / SASI_BITS_IN_BYTE);

    // Encrypt known data
    rc = SaSi_RSA_OAEP_Encrypt(pRndContext, pCcUserPubKey, pPrimeData, FIPS_RSA_HASH_TYPE, NULL, 0, SaSi_PKCS1_MGF1,
                               (uint8_t *)rsaFipsDataIn, sizeof(rsaFipsDataIn), (uint8_t *)pDataEncOut);
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_RSA_ENC_COND;
        goto End;
    }

    // Verify encrypted data is diffenet than the input
    rc = SaSi_PalMemCmp((uint8_t *)rsaFipsDataIn, pDataEncOut, sizeof(rsaFipsDataIn));
    if (rc == SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_RSA_ENC_COND;
        goto End;
    }

    // ecrypt th eencrypted data
    decDataSize = FIPS_RSA_DATA_SIZE;
    rc          = SaSi_RSA_OAEP_Decrypt(pCcUserPrivKey, pPrimeData, FIPS_RSA_HASH_TYPE, NULL, 0, SaSi_PKCS1_MGF1,
                               (uint8_t *)pDataEncOut, keySizeInBytes, (uint8_t *)pDataDecOut, &decDataSize);
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_RSA_DEC_COND;
        goto End;
    }

    // Verify decrypted data equals to input
    rc = SaSi_PalMemCmp((uint8_t *)rsaFipsDataIn, pDataDecOut, sizeof(rsaFipsDataIn));
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_RSA_DEC_COND;
        goto End;
    }
    rc = FipsSetTrace(CC_FIPS_TRACE_RSA_COND);
    if (rc != SaSi_OK) {
        rc = SaSi_FIPS_ERROR;
        goto End;
    }
End:
    if (rc != SaSi_OK) {
        FipsSetError(fipsRc);
        return SaSi_FIPS_ERROR;
    }
    return rc;

} /* END OF SaSi_FipsRsaConditionalTest */

// KAT for RSA:  use PKCS 2.1 for encrypt & decrypt, sign & verify
CC_FipsError_t SaSi_FipsRsaKat(SaSi_RND_Context_t *pRndContext, SaSi_RSAFipsKatContext_t *pFipsCtx)
{
    SaSiError_t rc        = SaSi_OK;
    CC_FipsError_t fipsRc = CC_TEE_FIPS_ERROR_OK;

    // set generate vector function, to return the expected vector according to test vectors
    rc = SaSi_RND_SetGenerateVectorFunc(pRndContext, fipsRsaKatGenVector);
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_GENERAL;
        goto End;
    }

    // perform encrypt & decrypt test
    fipsRc = fipsRsaKatEncryptTest(pRndContext, pFipsCtx);
    if (fipsRc != CC_TEE_FIPS_ERROR_OK) {
        goto End;
    }

    // perform sign & verify test
    fipsRc = fipsRsaKatSignTest(pRndContext, pFipsCtx);
    if (fipsRc != CC_TEE_FIPS_ERROR_OK) {
        goto End;
    }

    FipsSetTrace(CC_FIPS_TRACE_RSA_PUT);

End:

    SaSi_PalMemSetZero(pRndContext, sizeof(SaSi_RND_Context_t));
    SaSi_PalMemSetZero(pFipsCtx, sizeof(SaSi_RSAFipsKatContext_t));

    return fipsRc;
} /* SaSi_FipsRsaKat */
