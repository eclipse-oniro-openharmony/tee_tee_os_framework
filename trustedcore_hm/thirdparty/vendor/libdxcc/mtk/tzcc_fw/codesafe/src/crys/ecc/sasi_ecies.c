/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
/* SaSi level includes  */
#include "ssi_pal_mem.h"
#include "sasi_ecpki_types.h"
#include "sasi_ecpki_error.h"
#include "sasi_ecpki_local.h"
#include "sasi_ecpki_build.h"
#include "sasi_ecpki_kg.h"
#include "sasi_fips_defs.h"
#include "sasi_kdf.h"
#include "sasi_rnd.h"
#include "pka_ecc_export.h"

extern SaSiError_t SaSi_KDF_KeyDerivFunc_MTK(uint8_t *ZZSecret_ptr, uint32_t ZZSecretSize,
                                             SaSi_KDF_OtherInfo_t *OtherInfo_ptr, SaSi_KDF_HASH_OpMode_t KDFhashMode,
                                             SaSi_KDF_DerivFuncMode_t derivation_mode, uint8_t *KeyingData_ptr,
                                             uint32_t KeyingDataSizeBytes);

/* *********************** Defines *********************************** */

/* *********************** Enums ************************************* */

/* *********************** Typedefs ********************************** */

/* *********************** Global Data ******************************* */

/* ************ Private function prototype *************************** */

/* *********************** Public Functions ************************** */

/* **********************************************************************
 *                          _DX_ECIES_KemEncrypt                     *
 * ******************************************************************** */
/*
 @brief: The function creates and encrypts (encapsulate) the Secret Key of
     required size according to the ISO/IEC 18033-2 standard [1],
     sec. 10.2.3 - ECIES-KEM Encryption.

   For calling this function in applications must be used the macro
   definition SaSi_ECIES_KemEncrypt(). The function itself has additional input
   of external ephemeral key pair, used only for testing goals.

   The system parameters of the function, named in the standard [1] - sec. 10.2.1,
   are set as follows:
     - CofactorMode = 0, because all elliptic curves, used in SaSi, have cofactor = 1;
     - OldCofactorMode = 0 (according to previous);
     - CheckMode = 1 - means that checking of the recipient's public key should
       be performed;
     - SingleHashMode = 1 - for compliance with ANSI X9.63-2001;
     - Avaliable KDF functions are KDF1 or KDF2 ([1] - sec. 5.6.3).
       For compliance with ANSI X9.63-2001 must be used KDF2 function.

   The function performs the following:
     - Checks input parameters: pointers, buffers sizes etc.
     - Generates random ephemeral EC key pair by calling the SaSi_ECPKI_GenKeyPairCall
       function.
     - Converts the ephemeral public key to ciphertext by calling of the
       SaSi_ECPKI_ExportPublKey_MTK function.
     - Calls the LLF_ECPKI_SVDP_DH function to calculate the shared secret value SV.
     - Calls the _DX_KDF_KeyDerivFunc function to calculate the Secret Keying
       data using the secret value SV.
     - Exits.

   NOTE:
        1. The term "sender" indicates an entity, who creates and performs
       encapsulation of the Secret Key using this function. The term
       "recipient" indicates an other entity which receives and decrypts
       the Secret Key.
    2. All used public and private keys must relate to the same EC Domain.
    3. The recipient's public key, before using in this function, must be
       checked that it is on elliptic curve. For this goal the user may
       build the key structure using SaSi_ECPKI_BuildPublKeyPartlyCheck
       function.
    4. The function may be used also in Key Transport Schemes, in partial,
       in Integrated Encryption Scheme (ANSI X9.63-2001 5.8 - ECIES without
       optional SharedData).

 PARAMETERS:

 @param[in]  pRecipUzPublKey -  A pointer to the recipient's public key.
 @param[in]  kdfHashfMode -   An enumerator variable, defining the used HASH
                  function.
 @param[in]  kdfDerivMode -   An enumerator variable, defining which KDF function mode
                  is used KDF1 or KDF2 (see enumerator definition in SaSi_KDF.h).
 @param[in]  isSingleHashMode - Specific ECIES mode definition 0,1 according to [1] - sec.10.2.
 @param[in]  pEphUzPrivKey -    The pointer to the external ephemeral private key. This key is used
                  only for testing the function. In regular using the pointer should be
                  set to NULL and then the random key pair should be generated internally.
 @param[in]  pEphUzPublKey    - A pointer to the ephemeral public key related to the private key (must
                  be set to NULL if pEphUzPrivKey = NULL).
 @param[out] pSecrKey -       A pointer to the buffer for the Secret Key data to be generated.
 @param[in]  secrKeySize -    A size of the Secret Key data in bytes.
 @param[OUT] pCipherData -    A pointer to the encrypted cipher text.
 @param[in/OUT]  pCipherDataSize - A pointer to the size of the buffer for output of the CipherData (in)
                  and its actual size in bytes (out).
 @param[in]  pTempBuff -      A pointer to the temporary buffer of size
                  specified by the SaSi_ECPKI_ECIES_TempData_t
                  structure.
 @param [in] pFipsCtx -     Pointer to temporary buffer used in case FIPS certification if required
 @return  SaSiError_t:
        SaSi_OK
        SaSi_ECIES_INVALID_PUBL_KEY_PTR_ERROR
        SaSi_ECIES_INVALID_PUBL_KEY_TAG_ERROR
        SaSi_ECIES_INVALID_PUBL_KEY_VALUE_ERROR
        SaSi_ECIES_INVALID_KDF_DERIV_MODE_ERROR
        SaSi_ECIES_INVALID_KDF_HASH_MODE_ERROR
        SaSi_ECIES_INVALID_SECRET_KEY_PTR_ERROR
        SaSi_ECIES_INVALID_SECRET_KEY_SIZE_ERROR
        SaSi_ECIES_INVALID_CIPHER_DATA_PTR_ERROR
        SaSi_ECIES_INVALID_CIPHER_DATA_SIZE_PTR_ERROR
        SaSi_ECIES_INVALID_CIPHER_DATA_SIZE_ERROR
        SaSi_ECIES_INVALID_TEMP_DATA_PTR_ERROR
*/
CEXPORT_C SaSiError_t _DX_ECIES_KemEncrypt(SaSi_ECPKI_UserPublKey_t *pRecipUzPublKey,  /* in */
                                           SaSi_KDF_DerivFuncMode_t kdfDerivMode,      /* in */
                                           SaSi_KDF_HASH_OpMode_t kdfHashMode,         /* in */
                                           uint32_t isSingleHashMode,                  /* in */
                                           SaSi_ECPKI_UserPrivKey_t *pExtEphUzPrivKey, /* in */
                                           SaSi_ECPKI_UserPublKey_t *pExtEphUzPublKey, /* in */
                                           uint8_t *pSecrKey,                          /* out */
                                           uint32_t secrKeySize,                       /* in */
                                           uint8_t *pCipherData,                       /* out */
                                           uint32_t *pCipherDataSize,                  /* in/out */
                                           SaSi_ECIES_TempData_t *pTempBuff,           /* in */
                                           SaSi_RND_Context_t *pRndContext,            /* in */
                                           SaSi_ECPKI_KG_FipsContext_t *pFipsCtx)      /* in */
{
    /* LOCAL DECLARATIONS */

    SaSiError_t error;

    /*  pointer to EC domain  */
    const SaSi_ECPKI_Domain_t *pDomain;
    uint32_t modSizeInBytes, kdfDataSize;
    uint8_t *pKdfData;
    /* pointers to ephemeral key pair, which should be used */
    SaSi_ECPKI_UserPrivKey_t *pEphUzPrivKey;
    SaSi_ECPKI_UserPublKey_t *pEphUzPublKey;
    struct SaSi_ECPKI_PublKey_t *pRecipPublKey;
    SaSi_ECPKI_PrivKey_t *pEphPrivKey;

    /* FUNCTION LOGIC */

    /* Initialize Error */
    error = SaSi_OK;

    /* .........    checking the validity of input parameters  .......... */
    /* Note: pRndContext and pFipsCtx will be checked in called functions */
    /* ------------------------------------------------------------------- */

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* check the validity of the user static private key */
    if (pRecipUzPublKey == NULL)
        return SaSi_ECIES_INVALID_PUBL_KEY_PTR_ERROR;

    if (pRecipUzPublKey->valid_tag != SaSi_ECPKI_PUBL_KEY_VALIDATION_TAG)
        return SaSi_ECIES_INVALID_PUBL_KEY_TAG_ERROR;

    /* check KDF and HASH modes */
    if (kdfDerivMode != SaSi_KDF_ISO18033_KDF1_DerivMode && kdfDerivMode != SaSi_KDF_ISO18033_KDF2_DerivMode)
        return SaSi_ECIES_INVALID_KDF_DERIV_MODE_ERROR;

    /* check HASH mode */
    if (kdfHashMode > SaSi_KDF_HASH_NumOfModes)
        return SaSi_ECIES_INVALID_KDF_HASH_MODE_ERROR;

    /* check the Ephemeral key pair: must be both Null or both actual */
    if ((pExtEphUzPrivKey == NULL) ^ (pExtEphUzPublKey == NULL))
        return SaSi_ECIES_INVALID_EPHEM_KEY_PAIR_PTR_ERROR;

    if (pExtEphUzPrivKey != NULL && pExtEphUzPrivKey->valid_tag != SaSi_ECPKI_PRIV_KEY_VALIDATION_TAG)
        return SaSi_ECIES_INVALID_PRIV_KEY_TAG_ERROR;

    if (pExtEphUzPublKey != NULL && pExtEphUzPublKey->valid_tag != SaSi_ECPKI_PUBL_KEY_VALIDATION_TAG)
        return SaSi_ECIES_INVALID_PUBL_KEY_TAG_ERROR;

    /* check the pointer to the buffer for secret key output */
    if (pSecrKey == NULL)
        return SaSi_ECIES_INVALID_SECRET_KEY_PTR_ERROR;

    /* check the size of secret key to be generated */
    if (secrKeySize == 0)
        return SaSi_ECIES_INVALID_SECRET_KEY_SIZE_ERROR;

    /* checking the buffer for cipher text output */
    if (pCipherData == NULL)
        return SaSi_ECIES_INVALID_CIPHER_DATA_PTR_ERROR;

    if (pCipherDataSize == NULL)
        return SaSi_ECIES_INVALID_CIPHER_DATA_SIZE_PTR_ERROR;

    /* checking the temp buffer pointer  */
    if (pTempBuff == NULL)
        return SaSi_ECIES_INVALID_TEMP_DATA_PTR_ERROR;

    /* ..  initializtions  and other checking   .... */
    /* --------------------------------------------- */

    /* derive and check domainID from recipient Public Key */
    pRecipPublKey = (struct SaSi_ECPKI_PublKey_t *)&pRecipUzPublKey->PublKeyDbBuff;
    pDomain       = &pRecipPublKey->domain;

    /* check EC Domain ID */
    if (pDomain->DomainID >= SaSi_ECPKI_DomainID_OffMode)
        return SaSi_ECPKI_INVALID_DOMAIN_ID_ERROR;

    /* modulus size */
    modSizeInBytes = CALC_FULL_BYTES(pDomain->modSizeInBits);

    /* check cipher output buffer size */
    if (*pCipherDataSize < 2 * modSizeInBytes + 1)
        return SaSi_ECIES_INVALID_CIPHER_DATA_SIZE_ERROR;

    if (pExtEphUzPrivKey == NULL) {
        /* use internal genrated ephemeral Key Pair */
        error = SaSi_ECPKI_GenKeyPair_MTK(pRndContext, /* in/out */
                                          (const SaSi_ECPKI_Domain_t *)pDomain, &pTempBuff->PrivKey,
                                          &pTempBuff->PublKey, &pTempBuff->tmp.KgTempBuff, pFipsCtx);

        if (error != SaSi_OK)
            goto End;

        pEphUzPrivKey = &pTempBuff->PrivKey; // r
        pEphUzPublKey = &pTempBuff->PublKey; // g~ = r*G
    } else {
        /* use external ephemeral Key Pair */
        pEphUzPrivKey = pExtEphUzPrivKey;
        pEphUzPublKey = pExtEphUzPublKey;
    }

    /* convert ephemeral public key to standard form */
    error = SaSi_ECPKI_ExportPublKey_MTK(pEphUzPublKey,             /* in */
                                         SaSi_EC_PointUncompressed, /* in */
                                         (uint8_t *)&pTempBuff->zz, /* out */
                                         pCipherDataSize);
        /* in/out */ /* Number of Bytes that were copied to zz */
    if (error != SaSi_OK)
        goto End;

    /* call  LLF_ECPKI_SVDP_DH function to calculate the Secret Value */
    /* --------------------------------------------------------------- */ // h~ = r*h
    pEphPrivKey = (SaSi_ECPKI_PrivKey_t *)&pEphUzPrivKey->PrivKeyDbBuff;
    error       = LLF_ECPKI_SVDP_DH(
        pRecipPublKey,                                  /* in */
        (SaSi_ECPKI_PrivKey_t *)(pEphPrivKey->PrivKey), /* in */
        &((uint8_t *)&pTempBuff->zz)[*pCipherDataSize],
        /* out */ /* Next available space in zz where the (SV X coordinate of multiplication) will be stored */
        &pTempBuff->tmp.DhTempBuff); /* in */
    if (error != SaSi_OK)
        goto End;

    /* derive the Keying Data from the Secret Value by calling the KDF function    */
    /* --------------------------------------------------------------------------- */

    /* set pointer  and size of input data for KDF function */
    if (isSingleHashMode == SASI_TRUE) { /* z = X */
        pKdfData    = &((uint8_t *)&pTempBuff->zz)[*pCipherDataSize];
        kdfDataSize = modSizeInBytes;
    } else { /* z = C0 || X */
        pKdfData    = (uint8_t *)&pTempBuff->zz;
        kdfDataSize = *pCipherDataSize + modSizeInBytes;
    }

    /* derive the Keying Data */
    error = SaSi_KDF_KeyDerivFunc_MTK(pKdfData /* ZZSecret */, kdfDataSize /* ZZSecretSize */, NULL /* &otherInfo */,
                                      kdfHashMode, kdfDerivMode, pSecrKey, secrKeySize);
    if (error != SaSi_OK)
        goto End;

    /* Output of the Cipher Data (C0) = Ephemeral Public Key */
    SaSi_PalMemCopy(pCipherData, pTempBuff->zz, *pCipherDataSize);

End:
    if (error != SaSi_OK) {
        *pCipherDataSize = 0;
    }
    /* clean temp buffers */
    SaSi_PalMemSetZero(pTempBuff, sizeof(SaSi_ECIES_TempData_t));

    return error;

} /* END OF SaSi_ECIES_KemEncrypt */

/* **********************************************************************
 *                          SaSi_ECIES_KemDecrypt                       *
 * ******************************************************************** */
/*
 @brief: The function decrypts the encapsulated Secret Key passed by
     sender according to the ISO/IEC 18033-2 standard [1],
     sec. 10.2.4 - ECIES-KEM Decryption.

   The system parameters of the function, named in [1], sec. 10.2.1,
   are set as follows:
     - CofactorMode = 0, because all elliptic curves, used in SaSi, have
       cofactor = 1;
     - OldCofactorMode = 0 (according to previous);
     - CheckMode = 1 - means perform checking of ephemeral public key (mandatory
       in this case);
     - SingleHashMode = 1 - for compliance with ANSI X9.63-2001;
     - Avaliable KDF functions are KDF1 or KDF2 ([1] - sec. 5.6.3).
       For compliance with ANSI X9.63-2001 must be used KDF2 function.

   The function performs the following:
     - Checks input parameters: pointers, buffers sizes etc.
     - Checks, that the sender's ephemeral public key relates to
       used EC Domain and initializes the Key structure.
     - Calls the LLF_ECPKI_SVDP_DH function to calculate the secret value SV.
     - Calls the _DX_KDF_KeyDerivFunc function to calculate the Secret Keying
       data using secret value SV.
     - Exits.

   NOTE:
     1. The term "sender" indicates an entity, who creates and performs
    Encapsulation of the Secret Key using this function. The term
    "recipient" indicates an other entity which receives and decrypts
    the Cipher data and derives the Shared Secret Key.
     2. All used public and private keys must relate to the same EC Domain.
     3. The function may be used also in Key Transport Schemes, in partial,
    in Integrated Encryption Scheme (ANSI X9.63-2001 5.8 - ECIES without
    optional SharedData).

 PARAMETERS:

 @param[in]  pRecipUzPrivKey -  A pointer to the recipient's private key.
 @param[in]  kdfHashfMode -   An enumerator variable, defining used HASH function.
 @param[in]  kdfDerivMode -   An enumerator variable, defining which KDF function mode
                  is used KDF1 or KDF2 (see enumerator definition in SaSi_KDF.h).
 @param[in]  isSingleHashMode - Specific ECIES mode definition: 0,1 according to [1] - sec.10.2.
 @param[in]  pCipherData -    A pointer to the received encrypted cipher data.
 @param[in]  cipherDataSize - A size of the cipher data in bytes.
 @param[out] pSecrKey -       A pointer to the buffer for the Secret Key data to be generated.
 @param[in]  secrKeySize -    A size of the Secret Key data in bytes.
 @param[in]  pTempBuff -      A pointer to the temporary buffer of size
                  specified by the SaSi_ECPKI_ECIES_TempData_t
                  structure.
 @return  SaSiError_t:
        SaSi_OK
        SaSi_ECIES_INVALID_PRIV_KEY_PTR_ERROR
        SaSi_ECIES_INVALID_PRIV_KEY_TAG_ERROR
        SaSi_ECIES_INVALID_KDF_DERIV_MODE_ERROR
        SaSi_ECIES_INVALID_KDF_HASH_MODE_ERROR
        SaSi_ECIES_INVALID_CIPHER_DATA_PTR_ERROR
        SaSi_ECIEs_INVALID_CIPHER_DATA_SIZE_ERROR
        SaSi_ECIES_INVALID_SECRET_KEY_PTR_ERROR
        SaSi_ECIES_INVALID_SECRET_KEY_SIZE_ERROR
        SaSi_ECIES_INVALID_TEMP_DATA_PTR_ERROR
*/
CEXPORT_C SaSiError_t SaSi_ECIES_KemDecrypt(SaSi_ECPKI_UserPrivKey_t *pRecipUzPrivKey, /* in */
                                            SaSi_KDF_DerivFuncMode_t kdfDerivMode,     /* in */
                                            SaSi_KDF_HASH_OpMode_t kdfHashMode,        /* in */
                                            uint32_t isSingleHashMode,                 /* in */
                                            uint8_t *pCipherData,                      /* in */
                                            uint32_t cipherDataSize,                   /* in */
                                            uint8_t *pSecrKey,                         /* out */
                                            uint32_t secrKeySize,                      /* in */
                                            SaSi_ECIES_TempData_t *pTempBuff)          /* in */
{
    /* LOCAL DECLARATIONS */

    SaSiError_t error = SaSi_OK;

    /*  EC domain ID and info structure */
    const SaSi_ECPKI_Domain_t *pDomain;
    uint32_t modSizeInBytes, kdfDataSize;
    uint8_t *pKdfData;
    SaSi_ECPKI_PrivKey_t *pRecipPrivKey;

    /* ................. checking the validity of input parameters  .......... */
    /* ----------------------------------------------------------------------- */
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* check the validity of the recipient's private key */
    if (pRecipUzPrivKey == NULL)
        return SaSi_ECIES_INVALID_PRIV_KEY_PTR_ERROR;

    if (pRecipUzPrivKey->valid_tag != SaSi_ECPKI_PRIV_KEY_VALIDATION_TAG)
        return SaSi_ECIES_INVALID_PRIV_KEY_TAG_ERROR;

    /* check KDF and HASH modes */
    if (kdfDerivMode != SaSi_KDF_ISO18033_KDF1_DerivMode && kdfDerivMode != SaSi_KDF_ISO18033_KDF2_DerivMode)
        return SaSi_ECIES_INVALID_KDF_DERIV_MODE_ERROR;

    if (kdfHashMode > SaSi_KDF_HASH_NumOfModes)
        return SaSi_ECIES_INVALID_KDF_HASH_MODE_ERROR;

    /* check the pointer to the buffer for secret key output */
    if (pSecrKey == NULL)
        return SaSi_ECIES_INVALID_SECRET_KEY_PTR_ERROR;

    /* checking the size of secret key to be generated */
    if (secrKeySize == 0)
        return SaSi_ECIES_INVALID_SECRET_KEY_SIZE_ERROR;

    /* check the buffer for cipher text output */
    if (pCipherData == NULL)
        return SaSi_ECIES_INVALID_CIPHER_DATA_PTR_ERROR;

    /* checking the temp buffer pointer  */
    if (pTempBuff == NULL)
        return SaSi_ECIES_INVALID_TEMP_DATA_PTR_ERROR;

    /* ..  initializations  and other checking   .... */
    /* ---------------------------------------------- */

    /* derive domainID from recipient Private Key */
    pRecipPrivKey = (SaSi_ECPKI_PrivKey_t *)&(pRecipUzPrivKey->PrivKeyDbBuff);
    pDomain       = &pRecipPrivKey->domain;

    /* check EC Domain ID */
    if (pDomain->DomainID >= SaSi_ECPKI_DomainID_OffMode)
        return SaSi_ECPKI_INVALID_DOMAIN_ID_ERROR;

    /* modulus size */
    modSizeInBytes = CALC_FULL_BYTES(pDomain->modSizeInBits);

    /* partially check the cipher data C0 (ephemeral public key)
       and initialize appropriate SaSi Key structure */
    error = _DX_ECPKI_BuildPublKey_MTK(pDomain,                        /* in */
                                       pCipherData,                    /* in - ephem. publ.key data */
                                       cipherDataSize,                 /* in */
                                       ECpublKeyPartlyCheck,           /* in */
                                       &pTempBuff->PublKey,            /* out */
                                       &pTempBuff->tmp.buildTempbuff); /* in */
    if (error != SaSi_OK)
        goto End;

    /* call  LLF_ECPKI_SVDP_DH function to calculate the Secret Value SV */
    /* ----------------------------------------------------------------- */
    error = LLF_ECPKI_SVDP_DH((struct SaSi_ECPKI_PublKey_t *)&pTempBuff->PublKey.PublKeyDbBuff, /* in */
                              (SaSi_ECPKI_PrivKey_t *)pRecipPrivKey->PrivKey,            /* in */
                              &((uint8_t *)&pTempBuff->zz)[cipherDataSize],              /* out */
                              &pTempBuff->tmp.DhTempBuff);                               /* in */

    if (error != SaSi_OK)
        goto End;

    /* set pointer  and size of input data for KDF function */
    if (isSingleHashMode == SASI_TRUE) { /* zz = SV */
        pKdfData    = &((uint8_t *)&pTempBuff->zz)[cipherDataSize];
        kdfDataSize = modSizeInBytes;
    } else { /* zz = C0 || SV */
        pKdfData    = (uint8_t *)&pTempBuff->zz;
        kdfDataSize = cipherDataSize + modSizeInBytes;
        /* set cipherData  C0 in the temp buffer zz */
        SaSi_PalMemCopy((uint8_t *)&pTempBuff->zz, pCipherData, cipherDataSize);
    }

    /* derive the Keying Data from the ZZ Value by calling the KDF function */
    /* -----------------------------------------------------------------  - */
    error = SaSi_KDF_KeyDerivFunc_MTK(pKdfData /* ZZSecret */, kdfDataSize /* ZZSecretSize */, NULL /* &otherInfo */,
                                      kdfHashMode, kdfDerivMode, pSecrKey, secrKeySize);
End:
    /* clean temp buffers */
    SaSi_PalMemSetZero(pTempBuff, sizeof(SaSi_ECIES_TempData_t));

    return error;

} /* END OF SaSi_ECIES_KemDecrypt */
