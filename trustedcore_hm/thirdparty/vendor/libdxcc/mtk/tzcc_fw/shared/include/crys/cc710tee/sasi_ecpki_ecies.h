/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_ECPKI_ECIES_H
#define SaSi_ECPKI_ECIES_H

/* !
@file
@brief This file defines the APIs that support ECIES - EC Integrated Encryption Scheme.
*/

#include "sasi_ecpki_types.h"
#include "sasi_rnd.h"
#include "sasi_kdf.h"

#ifdef __cplusplus
extern "C" {
#endif

/* **********************************************************************
 *                          _DX_ECIES_KemEncrypt                        *
 * ******************************************************************** */
/*
 @brief The function creates and encrypts (encapsulate) a Secret Key of
     required size according to the ISO/IEC 18033-2 standard [1],
     sec. 10.2.3 - ECIES-KEM Encryption. In order to call this function the macro ::SaSi_ECIES_KemEncrypt
     should be used.

     The function does the following:
     <ul><li> Generates random ephemeral EC key pair</li>
     <li> Converts the ephemeral public key to ciphertext</li>
     <li> Calculates the shared secret value SV</li>
     <li> Calculates the Secret Keying data using the secret value SV.</li></ul>
 \note
    <ul id="noteb"><li> The term "sender" indicates an entity, who creates and performs encapsulation of the Secret Key
 using this function. The term "recipient" indicates another entity which receives and decrypts the Secret Key. </li>
    <li> All used public and private keys must be related to the same EC Domain. </li>
    <li> The recipient's public key must be a legal public key - on elliptic curve. </li>
    <li> The function may also be used in Key Transport Schemes and partially, in Integrated Encryption Scheme
    (ANSI X9.63-2001 5.8 - ECIES without optional SharedData). </li></ul>

 @return SaSi_OK on success.
 @return A non-zero value on failure as defined sasi_ecpki_error.h.
*/
CEXPORT_C SaSiError_t _DX_ECIES_KemEncrypt(
    SaSi_ECPKI_UserPublKey_t *pRecipUzPublKey, /* !< [in] A pointer to the recipient's public key. */
    SaSi_KDF_DerivFuncMode_t kdfDerivMode,     /* !< [in] An enumerator variable, defining which KDF function mode
                             is used KDF1 or KDF2 (as defined in SaSi_KDF.h). */
    SaSi_KDF_HASH_OpMode_t kdfHashMode,        /* !< [in] An enumerator variable, defining the used HASH function */
    uint32_t isSingleHashMode,                 /* !< [in] Specific ECIES mode definition 0,1 according to
                             ISO/IEC 18033-2 - sec.10.2. */
    SaSi_ECPKI_UserPrivKey_t
        *pExtEphUzPrivKey, /* !< [in] A pointer to external ephemeral private key - used only for testing */
    SaSi_ECPKI_UserPublKey_t
        *pExtEphUzPublKey,            /* !< [in] A pointer to external ephemeral public key - used only for testing */
    uint8_t *pSecrKey,                /* !< [out] Pointer to the generated Secret Key. */
    uint32_t secrKeySize,             /* !< [in] The size of the pSecrKey buffer in bytes. */
    uint8_t *pCipherData,             /* !< [out] A pointer to the encrypted ciphertext. */
    uint32_t *pCipherDataSize,        /* !< [in/out] A pointer to the size of the output cipher data (in)
                   and its actual size in bytes (out). */
    SaSi_ECIES_TempData_t *pTempBuff, /* !< [in] Temporary buffer for internal usage. */
    SaSi_RND_Context_t *pRndContext,  /* !< [in/out] Pointer to the RND context buffer. */
    SaSi_ECPKI_KG_FipsContext_t *pFipsCtx /* !< [in] Pointer to temporary buffer used in case FIPS
                        certification if required. */
);

/* **********************************************************************
 *                   SaSi_ECIES_KemEncrypt macros                        *
 * ******************************************************************** */
/*
 @brief A macro for creation and encryption of secret key. For a description of the parameters see
 ::_DX_ECIES_KemEncrypt.
*/
#define SaSi_ECIES_KemEncrypt(pRecipPublKey, kdfDerivMode, kdfHashMode, isSingleHashMode, pSecrKey, secrKeySize,     \
                              pCipherData, pCipherDataSize, pTempBuff, pRndCtx, pFipsCtx)                            \
    _DX_ECIES_KemEncrypt((pRecipPublKey), (kdfDerivMode), (kdfHashMode), (isSingleHashMode), NULL, NULL, (pSecrKey), \
                         (secrKeySize), (pCipherData), (pCipherDataSize), (pTempBuff), (pRndCtx), (pFipsCtx))

/* **********************************************************************
 *                          SaSi_ECIES_KemDecrypt                       *
 * ******************************************************************** */
/*
@brief The function decrypts the encapsulated Secret Key passed by the sender according to the ISO/IEC 18033-2 standard
[1], sec. 10.2.4 - ECIES-KEM Decryption.

       The function does the following
     <ul><li> Checks, that the sender's ephemeral public key relates to used EC Domain and initializes the Key
structure</li> <li> Calculates the shared secret value SV</li> <li> Calculates the Secret Keying data using the secret
value SV.</li></ul>

\note
    <ul id="noteb"><li> The term "sender" indicates an entity, who creates and performs encapsulation of the Secret Key
using this function. The term "recipient" indicates another entity which receives and decrypts the Secret Key. </li>
    <li> All used public and private keys must be related to the same EC Domain. </li>
    <li> The function may also be used in Key Transport Schemes and partially, in Integrated Encryption Scheme
    (ANSI X9.63-2001 5.8 - ECIES without optional SharedData). </li></ul>


 @return SaSi_OK on success.
 @return A non-zero value on failure as defined sasi_ecpki_error.h.
*/
CIMPORT_C SaSiError_t SaSi_ECIES_KemDecrypt(
    SaSi_ECPKI_UserPrivKey_t *pRecipPrivKey, /* !< [in] A pointer to the recipient's private key. */
    SaSi_KDF_DerivFuncMode_t kdfDerivMode,   /* !< [in] An enumerator variable, defining which KDF function mode
                          is used KDF1 or KDF2 (as defined in SaSi_KDF.h). */
    SaSi_KDF_HASH_OpMode_t kdfHashMode,      /* !< [in] An enumerator variable, defining used HASH function. */
    uint32_t isSingleHashMode,               /* !< [in] Specific ECIES mode definition 0,1 according to
                          ISO/IEC 18033-2 - sec.10.2. */
    uint8_t *pCipherData,                    /* !< [in] A pointer to the received encrypted cipher data. */
    uint32_t cipherDataSize,                 /* !< [in] A size of the cipher data in bytes. */
    uint8_t *pSecrKey,                       /* !< [out] Pointer to the generated Secret Key. */
    uint32_t secrKeySize,                    /* !< [in] The size of the pSecrKey buffer in bytes. */
    SaSi_ECIES_TempData_t *pTempBuff /* !< [in] Temporary buffer for internal usage. */);

#ifdef __cplusplus
}
#endif

#endif
