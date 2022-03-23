/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */

/* .............. SaSi level includes ................. */

#include "ssi_pal_mem.h"
#include "sasi_common.h"
#include "sasi_rsa_error.h"
#include "sasi_rsa_local.h"
#include "sasi_common_math.h"
#include "sasi_rnd_error.h"
#include "sasi_rsa_kg.h"
#include "llf_rsa.h"
#include "llf_rsa_public.h"
#include "llf_rsa_private.h"
#include "ssi_general_defs.h"
#include "sasi_fips_defs.h"

#ifdef DX_SOFT_KEYGEN
#include "ccsw_sasi_rsa_kg.h"
#endif

/* *********************** Defines **************************** */

/* canceling the lint warning:
   Use of goto is deprecated */


/* *********************** Enums ********************************** */

/* *********************** Typedefs ******************************* */

/* *********************** Global Data **************************** */

/*
 For debugging the RSA_KG module define the following flags in project properties
 and perform the following:
   1. Define LLF_PKI_PKA_DEBUG.
   2. For finding the bad random vactors (P,Q,P1pR,P2pR,P1qR,P2qR):
      define RSA_KG_FIND_BAD_RND flag, perform test and save (from memory) the finded bad vectors.
   3. For repeat the testing of finded bad vectors, write they as HW initialization of
      the following buffers: P=>RSA_KG_debugPvect, Q=>RSA_KG_debugQvect - in the SaSi_RSA_KG.c file,
      and P1pR=>rBuff1, P2pR=>rBuff1, P1qR=>rBuff3, P2qR=>rBuff4 in the LLF_PKI_GenKeyX931FindPrime.c file.
      Define the flag RSA_KG_NO_RND instead previously defined RSA_KG_FIND_BAD_RND flag and
      perform the test.
   4. For ordinary ATP or other tests (without debug) undefine all the named flags.
*/

#if ((defined RSA_KG_FIND_BAD_RND || defined RSA_KG_NO_RND) && defined DEBUG)
uint8_t RSA_KG_debugPvect[SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES] = {
    0x78, 0x71, 0xDF, 0xC5, 0x36, 0x98, 0x12, 0x21, 0xCA, 0xAC, 0x48, 0x22, 0x01, 0x94, 0xF7, 0x1A,
    0x1C, 0xBF, 0x82, 0xE9, 0x8A, 0xE4, 0x2C, 0x84, 0x43, 0x46, 0xCF, 0x6D, 0x60, 0xFB, 0x5B, 0xD3
};
uint8_t RSA_KG_debugQvect[SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES] = {
    0x46, 0x13, 0x9F, 0xBA, 0xBC, 0x8E, 0x21, 0x13, 0x35, 0x8C, 0x2C, 0x2D, 0xA8, 0xD6, 0x59, 0x78,
    0x8A, 0x14, 0x17, 0x5F, 0xA5, 0xEC, 0x22, 0xD5, 0x87, 0xF9, 0x99, 0x45, 0x1B, 0x38, 0xA3, 0xF0
};
#endif

/* ************ Private function prototype ************************ */

/* *********************** Public Functions **************************** */

/* ******************************************************************************************** */
#ifndef _INTERNAL_SaSi_NO_RSA_KG_SUPPORT
/*
   @brief SaSi_RSA_KG_GenerateKeyPair_MTK generates a Pair of public and private keys on non CRT mode.

   Note: FIPS 186-4 [5.1] standard specifies three choices for the length of the RSA
         keys (modules): 1024, 2048 and 3072 bits. This implementation allows
         generate also other (not FIPS approved) sizes on the user's responcibility.

   @param [in/out] rndContext_ptr  - Pointer to the RND context buffer.
   @param [in] PubExp_ptr - The pointer to the public exponent (public key)
   @param [in] PubExpSizeInBytes - The public exponent size in bytes.
   @param [in] KeySize  - The size of the key in bits. Supported sizes are 256 bit multiples
                          between 512 - 4096;
   @param [out] pCcUserPrivKey - A pointer to the private key structure.
                           This structure is used as input to the SaSi_RSA_PRIM_Decrypt_MTK API.
   @param [out] pCcUserPubKey - A pointer to the public key structure.
                           This structure is used as input to the SaSi_RSA_PRIM_Encrypt_MTK API.
   @param [in] KeyGenData_ptr - a pointer to a structure required for the KeyGen operation.

   @return SaSiError_t - SaSi_OK,
                         SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR,
                         SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
                         SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
                         SaSi_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
                         SaSi_RSA_INVALID_MODULUS_SIZE,
                         SaSi_RSA_INVALID_EXPONENT_SIZE
*/
CEXPORT_C SaSiError_t SaSi_RSA_KG_GenerateKeyPair_MTK(SaSi_RND_Context_t *rndContext_ptr, uint8_t *PubExp_ptr,
                                                      uint16_t PubExpSizeInBytes, uint32_t KeySize,
                                                      SaSi_RSAUserPrivKey_t *pCcUserPrivKey,
                                                      SaSi_RSAUserPubKey_t *pCcUserPubKey,
                                                      SaSi_RSAKGData_t *KeyGenData_ptr,
                                                      SaSi_RSAKGFipsContext_t *pFipsCtx)
{
    /* LOCAL INITIALIZATIONS AND DECLERATIONS */

    /* the error identifier */
    SaSiError_t Error = SaSi_OK;

    /* the pointers to the key structures */
    SaSiRSAPubKey_t *pCcPubKey;
    SaSiRSAPrivKey_t *pCcPrivKey;
    uint32_t *pP, *pQ;
    uint32_t pqSizeWords;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ...... checking the key database handle pointer .................... */
    if (PubExp_ptr == NULL)
        return SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR;

    /* ...... checking the validity of the exponent pointer ............... */
    if (pCcUserPrivKey == NULL)
        return SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the modulus pointer .............. */
    if (pCcUserPubKey == NULL)
        return SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the keygen data .................. */
    if (KeyGenData_ptr == NULL)
        return SaSi_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID;

    /* ...... checking the exponent size .................. */
    if (PubExpSizeInBytes > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
        return SaSi_RSA_INVALID_EXPONENT_SIZE;

    /* ...... checking the required key size ............................ */
    if ((KeySize < SaSi_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) || (KeySize > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS))
        return SaSi_RSA_INVALID_MODULUS_SIZE;

    /* set the public and private key structure pointers */
    pCcPubKey  = (SaSiRSAPubKey_t *)pCcUserPubKey->PublicKeyDbBuff;
    pCcPrivKey = (SaSiRSAPrivKey_t *)pCcUserPrivKey->PrivateKeyDbBuff;

    /* ................ clear all input structures ............................. */
    /* ------------------------------------------------------------------------- */

    SaSi_PalMemSetZero(pCcUserPrivKey, sizeof(SaSi_RSAUserPrivKey_t));
    SaSi_PalMemSetZero(pCcUserPubKey, sizeof(SaSi_RSAUserPubKey_t));
    SaSi_PalMemSetZero(KeyGenData_ptr, sizeof(SaSi_RSAKGData_t));

#ifdef DX_SOFT_KEYGEN
    if (KeySize >= DX_SOFT_KEYGEN_SIZE) {
        Error = SaSi_SW_RSA_KG_GenerateKeyPair(rndContext_ptr, (uint8_t *)PubExp_ptr, (uint16_t)PubExpSizeInBytes,
                                               (uint32_t)KeySize, (SW_SaSi_RSAUserPrivKey_t *)pCcUserPrivKey,
                                               (SW_SaSi_RSAUserPubKey_t *)pCcUserPubKey,
                                               (SW_SaSi_RSAKGData_t *)KeyGenData_ptr);

        /* ................ initialize the low level data .............. */
        Error = LLF_PKI_RSA_InitPubKeyDb(pCcPubKey);
        if (Error != SaSi_OK) {
            goto End;
        }

        Error = LLF_PKI_RSA_InitPrivKeyDb(pCcPrivKey);
        goto End;
    }
#endif

    /* ................ loading the public exponent to the structure .......... */
    /* ------------------------------------------------------------------------- */

    /* loading the buffers to start from LS word to MS word */
    Error =
        SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(pCcPubKey->e, sizeof(pCcPubKey->e), PubExp_ptr, PubExpSizeInBytes);
    if (Error != SaSi_OK) {
        goto End;
    }

    /* .......... initializing the effective counters size in bits .......... */
    pCcPubKey->eSizeInBits = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPubKey->e, (PubExpSizeInBytes + 3) / 4);

    /* if the size in bits is 0 - return error */
    if (pCcPubKey->eSizeInBits == 0 || pCcPubKey->eSizeInBits > 17) {
        Error = SaSi_RSA_INVALID_EXPONENT_SIZE;
        goto End;
    }

    /* verifying the exponent has legal value (currently only 0x3,0x11 and 0x10001) */
    if (pCcPubKey->e[0] != SaSi_RSA_KG_PUB_EXP_ALLOW_VAL_1 && pCcPubKey->e[0] != SaSi_RSA_KG_PUB_EXP_ALLOW_VAL_2 &&
        pCcPubKey->e[0] != SaSi_RSA_KG_PUB_EXP_ALLOW_VAL_3) {
        Error = SaSi_RSA_INVALID_EXPONENT_VAL;
        goto End;
    }

    /* .......... initialize the public key on the private structure ............... */

    SaSi_PalMemCopy(pCcPrivKey->PriveKeyDb.NonCrt.e, pCcPubKey->e, 4 * ((PubExpSizeInBytes + 3) / 4));
    pCcPrivKey->PriveKeyDb.NonCrt.eSizeInBits = pCcPubKey->eSizeInBits;

    /* .......... initializing the key size in bits ......................... */

    /* this initialization is required for the low level function (LLF) - indicates the required
    size of the key to be found */
    pCcPubKey->nSizeInBits  = KeySize;
    pCcPrivKey->nSizeInBits = KeySize;

    /* .......... set the private mode to non CRT .............................. */
    /* ------------------------------------------------------------------------- */

    /* set the mode to non CRT */
    pCcPrivKey->OperationMode = SaSi_RSA_NoCrt;

    /* set the key source as internal */
    pCcPrivKey->KeySource = SaSi_RSA_InternalKey;

    /* ................ executing the key generation ........................... */
    /* ------------------------------------------------------------------------- */
    pP          = KeyGenData_ptr->KGData.p;
    pQ          = KeyGenData_ptr->KGData.q;
    pqSizeWords = CALC_FULL_32BIT_WORDS(KeySize / 2);

    /* generate the random */
#if ((!defined RSA_KG_FIND_BAD_RND && !defined RSA_KG_NO_RND) || defined RSA_KG_FIND_BAD_RND || !defined DEBUG)

    while (1) {
        Error = SaSi_RSA_GenerateVectorInRangeX931(rndContext_ptr, pqSizeWords, pP);
        if (Error != SaSi_OK)
            goto End;

        Error = SaSi_RSA_GenerateVectorInRangeX931(rndContext_ptr, pqSizeWords, pQ);
        if (Error != SaSi_OK)
            goto End;

        /* check |p - q| > 2^((nSizeInBits/2)-100) */
        if (pP[pqSizeWords - 1] - pQ[pqSizeWords - 1] != 0 || pP[pqSizeWords - 2] - pQ[pqSizeWords - 2] != 0 ||
            pP[pqSizeWords - 3] - pQ[pqSizeWords - 3] != 0 ||
            ((pP[pqSizeWords - 4] - pQ[pqSizeWords - 4]) >> 28) != 0) {
            break;
        }
    }
#endif

#if (defined RSA_KG_FIND_BAD_RND && defined DEBUG)
    SaSi_PalMemCopy(RSA_KG_debugPvect, (uint8_t *)KeyGenData_ptr->KGData.p, KeySize / (2 * 8));
    SaSi_PalMemCopy(RSA_KG_debugQvect, (uint8_t *)KeyGenData_ptr->KGData.q, KeySize / (2 * 8));
#endif

#if (defined RSA_KG_NO_RND && defined DEBUG)
    SaSi_PalMemCopy((uint8_t *)KeyGenData_ptr->KGData.p, RSA_KG_debugPvect, KeySize / (2 * 8));
    SaSi_PalMemCopy((uint8_t *)KeyGenData_ptr->KGData.q, RSA_KG_debugQvect, KeySize / (2 * 8));
#endif

#if ((defined RSA_KG_FIND_BAD_RND || defined RSA_KG_NO_RND) && defined DEBUG)
#ifdef BIG__ENDIAN
    /* for big endiannes machine reverse bytes order in words according to Big Endian  */
    SaSi_COMMON_INVERSE_UINT32_IN_ARRAY(KeyGenData_ptr->KGData.p, KeySize / (2 * 32));
    SaSi_COMMON_INVERSE_UINT32_IN_ARRAY(KeyGenData_ptr->KGData.q, KeySize / (2 * 32));
#endif
#endif

    /* RL  clean the n-buffer */
    SaSi_PalMemSetZero(pCcPrivKey->n, 4 * SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS);

    /* ................ execute the low level keygen ........................... */
    Error = LLF_PKI_RSA_GenerateKeyPair(rndContext_ptr, pCcPubKey, pCcPrivKey, KeyGenData_ptr);

    /* on failure exit the function */
    if (Error != SaSi_OK)
        goto End;

    /* ................ initialize the low level key structures ................ */
    /* ------------------------------------------------------------------------- */

    Error = LLF_PKI_RSA_InitPubKeyDb(pCcPubKey);
    if (Error != SaSi_OK) {
        goto End;
    }

    Error = LLF_PKI_RSA_InitPrivKeyDb(pCcPrivKey);
    if (Error != SaSi_OK) {
        goto End;
    }

    /* ................ set the key valid tags ................................. */
    /* ------------------------------------------------------------------------- */
    pCcUserPrivKey->valid_tag = SaSi_RSA_PRIV_KEY_VALIDATION_TAG;
    pCcUserPubKey->valid_tag  = SaSi_RSA_PUB_KEY_VALIDATION_TAG;
    // run conditional test
    Error = FIPS_RSA_VALIDATE(rndContext_ptr, pCcUserPrivKey, pCcUserPubKey, pFipsCtx);

End:
    /* on failure clear the generated key */
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(pCcUserPrivKey, sizeof(SaSi_RSAUserPrivKey_t));
        SaSi_PalMemSetZero(pCcUserPubKey, sizeof(SaSi_RSAUserPubKey_t));
    }
    if (pFipsCtx != NULL) {
        SaSi_PalMemSetZero(pFipsCtx, sizeof(SaSi_RSAKGFipsContext_t));
    }
    /* clear the KG data structure */
    SaSi_PalMemSetZero(KeyGenData_ptr, sizeof(SaSi_RSAKGData_t));
    return Error;

} /* END OF SaSi_RSA_KG_GenerateKeyPair_MTK */

/* ******************************************************************************************** */
/*
   @brief SaSi_RSA_KG_GenerateKeyPairCRT_MTK generates a Pair of public and private keys on CRT mode.

   Note: FIPS 186-4 [5.1] standard specifies three choices for the length of the RSA
         keys (modules): 1024, 2048 and 3072 bits. This implementation allows
         generate also some other (not FIPS approved) sizes on the user's responcibility.

   @param [in/out] rndContext_ptr  - Pointer to the RND context buffer.
   @param [in] PubExp_ptr - The pointer to the public exponent (public key)
   @param [in] PubExpSizeInBytes - The public exponent size in bits.
   @param [in] KeySize  - The size of the key in bits. Supported sizes are 256 bit multiples
                          between 512 - 4096;
   @param [out] pCcUserPrivKey - A pointer to the private key structure.
                           This structure is used as input to the SaSi_RSA_PRIM_Decrypt_MTK API.
   @param [out] pCcUserPubKey - A pointer to the public key structure.
                           This structure is used as input to the SaSi_RSA_PRIM_Encryped API.
   @param [in] KeyGenData_ptr - a pointer to a structure required for the KeyGen operation.

   @return SaSiError_t - SaSi_OK,
                         SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR,
                         SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
                         SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
                         SaSi_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
                         SaSi_RSA_INVALID_MODULUS_SIZE,
                         SaSi_RSA_INVALID_EXPONENT_SIZE
*/

CEXPORT_C SaSiError_t SaSi_RSA_KG_GenerateKeyPairCRT_MTK(SaSi_RND_Context_t *rndContext_ptr, uint8_t *PubExp_ptr,
                                                         uint16_t PubExpSizeInBytes, uint32_t KeySize,
                                                         SaSi_RSAUserPrivKey_t *pCcUserPrivKey,
                                                         SaSi_RSAUserPubKey_t *pCcUserPubKey,
                                                         SaSi_RSAKGData_t *KeyGenData_ptr,
                                                         SaSi_RSAKGFipsContext_t *pFipsCtx)
{
    /* LOCAL INITIALIZATIONS AND DECLERATIONS */

    /* the error identifier */
    SaSiError_t Error = SaSi_OK;

    /* the pointers to the key structures */
    SaSiRSAPubKey_t *pCcPubKey;
    SaSiRSAPrivKey_t *pCcPrivKey;
    uint32_t pSizeWords;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ...... checking the key database handle pointer .................. */
    if (PubExp_ptr == NULL)
        return SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR;

    /* ...... checking the validity of the exponent pointer ............. */
    if (pCcUserPrivKey == NULL)
        return SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the modulus pointer .............. */
    if (pCcUserPubKey == NULL)
        return SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the keygen data .................. */
    if (KeyGenData_ptr == NULL)
        return SaSi_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID;

    /* ...... checking the required key size ............................ */
    if ((KeySize < SaSi_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (KeySize > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS)) {
        return SaSi_RSA_INVALID_MODULUS_SIZE;
    }

    /* set the public and private key structure pointers */
    pCcPubKey  = (SaSiRSAPubKey_t *)pCcUserPubKey->PublicKeyDbBuff;
    pCcPrivKey = (SaSiRSAPrivKey_t *)pCcUserPrivKey->PrivateKeyDbBuff;

    /* ................ clear all input structures ............................. */
    /* ------------------------------------------------------------------------- */

    SaSi_PalMemSetZero(pCcUserPrivKey, sizeof(SaSi_RSAUserPrivKey_t));
    SaSi_PalMemSetZero(pCcUserPubKey, sizeof(SaSi_RSAUserPubKey_t));
    SaSi_PalMemSetZero(KeyGenData_ptr, sizeof(SaSi_RSAKGData_t));

#ifdef DX_SOFT_KEYGEN
    if (KeySize >= DX_SOFT_KEYGEN_SIZE) {
        Error = SaSi_SW_RSA_KG_GenerateKeyPairCRT(rndContext_ptr, (uint8_t *)PubExp_ptr, (uint16_t)PubExpSizeInBytes,
                                                  (uint32_t)KeySize, (SW_SaSi_RSAUserPrivKey_t *)pCcUserPrivKey,
                                                  (SW_SaSi_RSAUserPubKey_t *)pCcUserPubKey,
                                                  (SW_SaSi_RSAKGData_t *)KeyGenData_ptr);

        /* ................ initialize the low level data .............. */
        Error = LLF_PKI_RSA_InitPubKeyDb(pCcPubKey);
        if (Error != SaSi_OK) {
        }

        Error = LLF_PKI_RSA_InitPrivKeyDb(pCcPrivKey);
        goto End;
    }
#endif

    /* ................ loading the public exponent to the structure .......... */
    /* ------------------------------------------------------------------------- */

    /* loading the buffers to start from LS word to MS word */
    Error =
        SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(pCcPubKey->e, sizeof(pCcPubKey->e), PubExp_ptr, PubExpSizeInBytes);
    if (Error != SaSi_OK) {
        goto End;
    }

    /* .......... initializing the effective counters size in bits .......... */
    pCcPubKey->eSizeInBits = SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPubKey->e, (PubExpSizeInBytes + 3) / 4);

    /* if the size in bits is 0 - return error */
    if (pCcPubKey->eSizeInBits == 0 || pCcPubKey->eSizeInBits > 17) {
        Error = SaSi_RSA_INVALID_EXPONENT_SIZE;
        goto End;
    }

    /* verifing the exponent has legal value (currently only 0x3,0x11 and 0x10001) */
    /* verifying the exponent has legal value (currently only 0x3,0x11 and 0x10001) */
    if (pCcPubKey->e[0] != SaSi_RSA_KG_PUB_EXP_ALLOW_VAL_1 && pCcPubKey->e[0] != SaSi_RSA_KG_PUB_EXP_ALLOW_VAL_2 &&
        pCcPubKey->e[0] != SaSi_RSA_KG_PUB_EXP_ALLOW_VAL_3) {
        Error = SaSi_RSA_INVALID_EXPONENT_VAL;
        goto End;
    }

    /* .......... initializing the key sizes  ......................... */

    pSizeWords = KeySize / 64; // RL
    /* this initialization is required for the low level function (LLF) - indicates the required
       size of the key to be found */
    pCcPubKey->nSizeInBits  = KeySize;
    pCcPrivKey->nSizeInBits = KeySize;

    /* .......... set the private mode to CRT .................................. */
    /* ------------------------------------------------------------------------- */

    /* set the mode to CRT */
    pCcPrivKey->OperationMode = SaSi_RSA_Crt;

    /* set the key source as internal */
    pCcPrivKey->KeySource = SaSi_RSA_InternalKey;

    /* ................ executing the key generation ........................... */
    /* ------------------------------------------------------------------------- */

    /* ................ generate the prime1 and prime2 random numbers .......... */

    /* generate the random */
    Error = SaSi_RSA_GenerateVectorInRangeX931(rndContext_ptr, pSizeWords, KeyGenData_ptr->KGData.p);
    if (Error != SaSi_OK)
        goto End;

    Error = SaSi_RSA_GenerateVectorInRangeX931(rndContext_ptr, pSizeWords, KeyGenData_ptr->KGData.q);
    if (Error != SaSi_OK)
        goto End;

    /* ................ execute the low level key gen ........................... */
    Error = LLF_PKI_RSA_GenerateKeyPair(rndContext_ptr, pCcPubKey, pCcPrivKey, KeyGenData_ptr);

    /* on failure exit the function */
    if (Error != SaSi_OK)
        goto End;

    /* ................ set the vector sizes ................................... */
    /* ------------------------------------------------------------------------- */

    pCcPrivKey->PriveKeyDb.Crt.PSizeInBits =
        SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPrivKey->PriveKeyDb.Crt.P, (uint16_t)pSizeWords);

    pCcPrivKey->PriveKeyDb.Crt.QSizeInBits =
        SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPrivKey->PriveKeyDb.Crt.Q, (uint16_t)pSizeWords);

    pCcPrivKey->PriveKeyDb.Crt.dPSizeInBits =
        SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPrivKey->PriveKeyDb.Crt.dP, (uint16_t)pSizeWords);

    pCcPrivKey->PriveKeyDb.Crt.dQSizeInBits =
        SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPrivKey->PriveKeyDb.Crt.dQ, (uint16_t)pSizeWords);

    pCcPrivKey->PriveKeyDb.Crt.qInvSizeInBits =
        SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPrivKey->PriveKeyDb.Crt.qInv, (uint16_t)pSizeWords);

    /* ................ initialize the low level key structures ................ */
    /* ------------------------------------------------------------------------- */

    Error = LLF_PKI_RSA_InitPubKeyDb(pCcPubKey);

    if (Error != SaSi_OK)
        goto End;

    Error = LLF_PKI_RSA_InitPrivKeyDb(pCcPrivKey);

    if (Error != SaSi_OK)
        goto End;

    pCcUserPrivKey->valid_tag = SaSi_RSA_PRIV_KEY_VALIDATION_TAG;
    pCcUserPubKey->valid_tag  = SaSi_RSA_PUB_KEY_VALIDATION_TAG;
    // run conditional test
    Error = FIPS_RSA_VALIDATE(rndContext_ptr, pCcUserPrivKey, pCcUserPubKey, pFipsCtx);

End:
    /* on failure clear the generated key */
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(pCcUserPrivKey, sizeof(SaSi_RSAUserPrivKey_t));
        SaSi_PalMemSetZero(pCcUserPubKey, sizeof(SaSi_RSAUserPubKey_t));
    }
    if (pFipsCtx != NULL) {
        SaSi_PalMemSetZero(pFipsCtx, sizeof(SaSi_RSAKGFipsContext_t));
    }
    /* clear the KG data structure */
    SaSi_PalMemSetZero(KeyGenData_ptr, sizeof(SaSi_RSAKGData_t));

    return Error;

} /* END OF SaSi_RSA_KG_GenerateKeyPairCRT_MTK */

/* ******************************************************************************************************* */
/*
 * @brief The SaSi_RSA_GenerateVectorInRangeX931 function generates a random vector in range:
 *            MinVect < RandVect < MaxVect, where:
 *            MinVect = squareRoot(2) * 2^(RndSizeInBits-1),  MaxVect = 2^RndSizeInBits.
 *
 *            Note: 1. MSBit of RandVect must be set to 1.
 *                  2. Words order of output vector is set from LS word to MS
 *                 word.
 *
 *        This function is used in PKI RSA for random generation according to ANS X9.31 standard.
 *        If PKI_RSA is not supported, the function does nothing.
 *
 *        Functions algorithm::
 *
 *        1.  Calls the SaSi_RND_GenerateVector_MTK() function for generating random vector
 *            RndVect of size RndSizeInWords, rounded up to bytes. Set index i
 *            to high word i = SizeInWords-1.
 *        2.  Check and adust candidate for msWord inside the random vector
 *            starting from msWord himselv, if msWord > high word of MinVect,
 *            goto step 3, else try next word i--; if no words to try, then goto
 *            step 1.
 *        3.  Set the found msWord to high position in array and generate new
 *            random words instead all checked and rejected words.
 *
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 * @rndSizeWords[in]  - The size of random vectore that is required.
 * @rnd_ptr[out]      - The output buffer of size not less, than rndSizeWords.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                       value MODULE_* as defined in ...
 */
SaSiError_t SaSi_RSA_GenerateVectorInRangeX931(SaSi_RND_Context_t *rndContext_ptr, uint32_t rndSizeWords,
                                               uint32_t *rnd_ptr)
{
    /* MIN_WORD = rounded up MS word of (2^(32*rndSizeWords-1))*sqwRoot(2) */
#define MIN_VAL 0xB504F334 /* RL minimal value of MS word of rnd vect. */

    /* FUNCTION DECLARATIONS */

    SaSiError_t error = SaSi_OK;
    uint32_t msWord;
    int32_t i;
    SaSiBool_t isFound = SASI_FALSE;
    SaSi_RND_State_t *rndState_ptr;
    SaSiRndGenerateVectWorkFunc_t RndGenerateVectFunc;

    /* FUNCTION LOGIC */

    /* check parameters */
    if (rndContext_ptr == NULL)
        return SaSi_RND_CONTEXT_PTR_INVALID_ERROR;

    rndState_ptr        = &(rndContext_ptr->rndState);
    RndGenerateVectFunc = rndContext_ptr->rndGenerateVectFunc;

    if (RndGenerateVectFunc == NULL)
        return SaSi_RND_GEN_VECTOR_FUNC_ERROR;

    /* .........         Rnd generation       .............. */
    /* ----------------------------------------------------- */

    while (1) {
        /* Genrate random prime candidate, considered as 32-bit words */
        error = RndGenerateVectFunc(rndState_ptr, (uint16_t)rndSizeWords * sizeof(uint32_t), (uint8_t *)rnd_ptr);
        if (error)
            goto End;

        /* Find and adust candidate for msWord inside the random *
         *  vector starting from msWord itself             */

        for (i = rndSizeWords - 1; i >= 0; i--) {
            /* Set MSBit to 1 */
            msWord = rnd_ptr[i] | 0x80000000;

            if (msWord > MIN_VAL) {
                rnd_ptr[rndSizeWords - 1] = msWord;
                isFound                   = 1;
            }

            /* Generate new random words instead the checked yet  *
             *  (for sequrity goals)                   */
            if ((isFound == 1) && (i < (int32_t)rndSizeWords - 1)) {
                error = RndGenerateVectFunc(rndState_ptr, (uint16_t)(rndSizeWords - 1 - i) * sizeof(uint32_t),
                                            (uint8_t *)&rnd_ptr[i]);
                if (error)
                    goto End;
            }

            if (isFound == 1)
                break;
        }

        if (isFound) {
            rnd_ptr[0] |= 1; /* ensure odd result */
            break;
        }
    }

End:
    return error;

} /* End of SaSi_RSA_GenerateVectorInRangeX931 */

#endif /* _INTERNAL_SaSi_NO_RSA_KG_SUPPORT */
