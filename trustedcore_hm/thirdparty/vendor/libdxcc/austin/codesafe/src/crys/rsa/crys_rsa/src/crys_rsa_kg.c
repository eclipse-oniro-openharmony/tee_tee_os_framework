/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

/* ************ Include Files ************** */

/* .............. CRYS level includes ................. */

#include "dx_pal_mem.h"
#include "crys.h"
#include "crys_common.h"
#include "crys_rsa_error.h"
#include "crys_rsa_local.h"
#include "crys_common_math.h"
#ifndef CRYS_NO_RSA_SELF_TEST_SUPPORT
#include "crys_self_test_local.h"
#endif

#ifdef DX_SOFT_KEYGEN
#include "ccsw_crys_rsa_kg.h"
#endif

/* .............. LLF level includes ................. */

#if !defined(CRYS_NO_HASH_SUPPORT) && !defined(CRYS_NO_PKI_SUPPORT)
#include "llf_pki_rsa.h"
#include "cc_acl.h"
#endif /* !defined(CRYS_NO_HASH_SUPPORT) && !defined(CRYS_NO_PKI_SUPPORT) */

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
      the following buffers: P=>RSA_KG_debugPvect, Q=>RSA_KG_debugQvect - in the CRYS_RSA_KG.c file,
      and P1pR=>rBuff1, P2pR=>rBuff1, P1qR=>rBuff3, P2qR=>rBuff4 in the LLF_PKI_GenKeyX931FindPrime.c file.
      Define the flag RSA_KG_NO_RND instead previously defined RSA_KG_FIND_BAD_RND flag and
      perform the test.
   4. For ordinary ATP or other tests (without debug) undefine all the named flags.
*/

#if ((defined RSA_KG_FIND_BAD_RND || defined RSA_KG_NO_RND) && defined DEBUG)
uint8_t RSA_KG_debugPvect[CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES] = {
    0x78, 0x71, 0xDF, 0xC5, 0x36, 0x98, 0x12, 0x21, 0xCA, 0xAC, 0x48, 0x22, 0x01, 0x94, 0xF7, 0x1A,
    0x1C, 0xBF, 0x82, 0xE9, 0x8A, 0xE4, 0x2C, 0x84, 0x43, 0x46, 0xCF, 0x6D, 0x60, 0xFB, 0x5B, 0xD3
};
uint8_t RSA_KG_debugQvect[CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES] = {
    0x46, 0x13, 0x9F, 0xBA, 0xBC, 0x8E, 0x21, 0x13, 0x35, 0x8C, 0x2C, 0x2D, 0xA8, 0xD6, 0x59, 0x78,
    0x8A, 0x14, 0x17, 0x5F, 0xA5, 0xEC, 0x22, 0xD5, 0x87, 0xF9, 0x99, 0x45, 0x1B, 0x38, 0xA3, 0xF0
};
#endif

/* ************ Private function prototype ************************ */

/* *********************** Public Functions **************************** */

/* ******************************************************************************************** */
#ifndef _INTERNAL_CRYS_NO_RSA_KG_SUPPORT
/*
   @brief CRYS_RSA_KG_GenerateKeyPair generates a Pair of public and private keys on non CRT mode.

   @param[in] PubExp_ptr - The pointer to the public exponent (public key)
   @param[in] PubExpSizeInBytes - The public exponent size in bytes.
   @param[in] KeySize  - The size of the key, in bits. Supported sizes are:
                - for PKI without PKA HW: all 256 bit multiples between 512 - 2048;
                - for PKI with PKA: HW all 32 bit multiples between 512 - 2112;
   @param[out] pCcUserPrivKey - A pointer to the private key structure.
               This structure is used as input to the CRYS_RSA_PRIM_Decrypt API.
   @param[out] pCcUserPubKey - A pointer to the public key structure.
               This structure is used as input to the CRYS_RSA_PRIM_Encrypt API.
   @param[in] KeyGenData_ptr - a pointer to a structure required for the KeyGen operation.

   @return CRYSError_t - CRYS_OK,
             CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR,
             CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
             CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
             CRYS_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
             CRYS_RSA_INVALID_MODULUS_SIZE,
             CRYS_RSA_INVALID_EXPONENT_SIZE
*/
CEXPORT_C CRYSError_t CRYS_RSA_KG_GenerateKeyPair(uint8_t *PubExp_ptr, uint16_t PubExpSizeInBytes, uint32_t KeySize,
                                                  CRYS_RSAUserPrivKey_t *pCcUserPrivKey,
                                                  CRYS_RSAUserPubKey_t *pCcUserPubKey, CRYS_RSAKGData_t *KeyGenData_ptr)
{
    /* LOCAL INITIALIZATIONS AND DECLERATIONS */

    /* the error identifier */
    CRYSError_t Error = CRYS_OK;

    /* the pointers to the key structures */
    CRYSRSAPubKey_t *pCcPubKey;
    CRYSRSAPrivKey_t *pCcPrivKey;

#ifndef CRYS_NO_RSA_SELF_TEST_SUPPORT
    /* Data for Conditional test, after Key - Generation */
    const uint8_t Data_ptr[] = { 'D', 'i', 's', 'c', 'r', 'e', 't', 'i', 'x' };
    uint16_t DataSize        = sizeof(Data_ptr);
#endif

    /* FUNCTION LOGIC */

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* ................. checking the validity of the pointer arguments ....... */
    /* ------------------------------------------------------------------------ */

    /* ...... checking the key database handle pointer .................... */
    if (PubExp_ptr == DX_NULL)
        return CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR;

    /* ...... checking the validity of the exponent pointer ............... */
    if (pCcUserPrivKey == DX_NULL)
        return CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the modulus pointer .............. */
    if (pCcUserPubKey == DX_NULL)
        return CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the keygen data .................. */
    if (KeyGenData_ptr == DX_NULL)
        return CRYS_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID;

    /* ...... checking the exponent size .................. */
    if (PubExpSizeInBytes > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
        return CRYS_RSA_INVALID_EXPONENT_SIZE;

    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ, PubExp_ptr, PubExpSizeInBytes) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, pCcUserPrivKey, sizeof(CRYS_RSAUserPrivKey_t)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, pCcUserPubKey, sizeof(CRYS_RSAUserPubKey_t)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, KeyGenData_ptr, sizeof(CRYS_RSAKGData_t))) {
        return CRYS_RSA_ILLEGAL_PARAMS_ACCORDING_TO_PRIV_ERROR;
    }

    /* ...... checking the required key size ............................ */
    if ((KeySize < CRYS_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (KeySize >= CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (KeySize % CRYS_RSA_VALID_KEY_SIZE_MULTIPLE_VALUE_IN_BITS))
        return CRYS_RSA_INVALID_MODULUS_SIZE;

    /* set the public and private key structure pointers */
    pCcPubKey  = (CRYSRSAPubKey_t *)pCcUserPubKey->PublicKeyDbBuff;
    pCcPrivKey = (CRYSRSAPrivKey_t *)pCcUserPrivKey->PrivateKeyDbBuff;

    /* ................ clear all input structures ............................. */
    /* ------------------------------------------------------------------------- */

    DX_PAL_MemSet(pCcUserPrivKey, 0, sizeof(CRYS_RSAUserPrivKey_t));
    DX_PAL_MemSet(pCcUserPubKey, 0, sizeof(CRYS_RSAUserPubKey_t));
    DX_PAL_MemSet(KeyGenData_ptr, 0, sizeof(CRYS_RSAKGData_t));

#ifdef DX_SOFT_KEYGEN
    if (KeySize >= DX_SOFT_KEYGEN_SIZE) {
        Error = CRYS_SW_RSA_KG_GenerateKeyPair((uint8_t *)PubExp_ptr, (uint16_t)PubExpSizeInBytes, (uint32_t)KeySize,
                                               (SW_CRYS_RSAUserPrivKey_t *)pCcUserPrivKey,
                                               (SW_CRYS_RSAUserPubKey_t *)pCcUserPubKey,
                                               (SW_CRYS_RSAKGData_t *)KeyGenData_ptr);

        /* ................ initialize the low level data .............. */
        Error = LLF_PKI_RSA_InitPubKeyDb(pCcPubKey);

        if (Error)
            return Error;

        Error = LLF_PKI_RSA_InitPrivKeyDb(pCcPrivKey);

        return Error;
    }
#endif

    /* ................ loading the public exponent to the structure .......... */
    /* ------------------------------------------------------------------------- */

    /* loading the buffers to start from LS word to MS word */
    Error =
        CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(pCcPubKey->e, sizeof(pCcPubKey->e), PubExp_ptr, PubExpSizeInBytes);
    if (Error != CRYS_OK)
        return Error;

    /* .......... initializing the effective counters size in bits .......... */
    pCcPubKey->eSizeInBits = CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPubKey->e, (PubExpSizeInBytes + 3) / 4);

    /* if the size in bits is 0 - return error */
    if (pCcPubKey->eSizeInBits == 0 || pCcPubKey->eSizeInBits > 17) {
        Error = CRYS_RSA_INVALID_EXPONENT_SIZE;
        goto End;
    }

    /* verifying the exponent has legal value (currently only 0x3,0x11 and 0x10001) */
    if (pCcPubKey->e[0] != CRYS_RSA_KG_PUB_EXP_ALLOW_VAL_1 && pCcPubKey->e[0] != CRYS_RSA_KG_PUB_EXP_ALLOW_VAL_2 &&
        pCcPubKey->e[0] != CRYS_RSA_KG_PUB_EXP_ALLOW_VAL_3) {
        Error = CRYS_RSA_INVALID_EXPONENT_VAL;
        goto End;
    }

    /* .......... initialize the public key on the private structure ............... */

    DX_PAL_MemCopy(pCcPrivKey->PriveKeyDb.NonCrt.e, pCcPubKey->e, 4 * ((PubExpSizeInBytes + 3) / 4));
    pCcPrivKey->PriveKeyDb.NonCrt.eSizeInBits = pCcPubKey->eSizeInBits;

    /* .......... initializing the key size in bits ......................... */

    /* this initialization is required for the low level function (LLF) - indicates the required
    size of the key to be found */
    pCcPubKey->nSizeInBits  = KeySize;
    pCcPrivKey->nSizeInBits = KeySize;

    /* .......... set the private mode to non CRT .............................. */
    /* ------------------------------------------------------------------------- */

    /* set the mode to non CRT */
    pCcPrivKey->OperationMode = CRYS_RSA_NoCrt;

    /* set the key source as internal */
    pCcPrivKey->KeySource = CRYS_RSA_InternalKey;

    /* ................ executing the key generation ........................... */
    /* ------------------------------------------------------------------------- */

    /* generate the random */
#if ((!defined RSA_KG_FIND_BAD_RND && !defined RSA_KG_NO_RND) || defined RSA_KG_FIND_BAD_RND || !defined DEBUG)
    Error = CRYS_RSA_GenerateVectorInRangeX931(KeySize / (2 * 32), KeyGenData_ptr->KGData.p);
    if (Error != CRYS_OK)
        goto End;

    Error = CRYS_RSA_GenerateVectorInRangeX931(KeySize / (2 * 32), KeyGenData_ptr->KGData.q);
    if (Error != CRYS_OK)
        goto End;
#endif

#if (defined RSA_KG_FIND_BAD_RND && defined DEBUG)
    DX_PAL_MemCopy(RSA_KG_debugPvect, (uint8_t *)KeyGenData_ptr->KGData.p, KeySize / (2 * 8));
    DX_PAL_MemCopy(RSA_KG_debugQvect, (uint8_t *)KeyGenData_ptr->KGData.q, KeySize / (2 * 8));
#endif

#if (defined RSA_KG_NO_RND && defined DEBUG)
    DX_PAL_MemCopy((uint8_t *)KeyGenData_ptr->KGData.p, RSA_KG_debugPvect, KeySize / (2 * 8));
    DX_PAL_MemCopy((uint8_t *)KeyGenData_ptr->KGData.q, RSA_KG_debugQvect, KeySize / (2 * 8));
#endif

#if ((defined RSA_KG_FIND_BAD_RND || defined RSA_KG_NO_RND) && defined DEBUG)
#ifdef BIG__ENDIAN
    /* for big endiannes machine reverse bytes order in words according to Big Endian  */
    CRYS_COMMON_INVERSE_UINT32_IN_ARRAY(KeyGenData_ptr->KGData.p, KeySize / (2 * 32));
    CRYS_COMMON_INVERSE_UINT32_IN_ARRAY(KeyGenData_ptr->KGData.q, KeySize / (2 * 32));
#endif
#endif

    /* clean the n-buffer */
    DX_PAL_MemSetZero(pCcPrivKey->n, 4 * CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS);

    /* ................ execute the low level keygen ........................... */
    Error = LLF_PKI_RSA_GenerateKeyPair(pCcPubKey, pCcPrivKey, KeyGenData_ptr);

    /* on failure exit the function */
    if (Error != CRYS_OK)
        goto End;

    /* ................ initialize the low level key structures ................ */
    /* ------------------------------------------------------------------------- */

    Error = LLF_PKI_RSA_InitPubKeyDb(pCcPubKey);

    if (Error != CRYS_OK)
        goto End;

    Error = LLF_PKI_RSA_InitPrivKeyDb(pCcPrivKey);

    if (Error != CRYS_OK)
        goto End;

        /* ............... START : Conditional test for Key-Generation ............. */
        /* ------------------------------------------------------------------------- */

#ifndef CRYS_NO_RSA_SELF_TEST_SUPPORT

    /* Clean and fill the data buffer */
    DX_PAL_MemSet(KeyGenData_ptr->PrimData.DataIn, 0, CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 4);
    DX_PAL_MemSet(KeyGenData_ptr->PrimData.DataOut, 0, CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 4);
    DX_PAL_MemCopy(KeyGenData_ptr->PrimData.DataIn, Data_ptr, DataSize);

    /* Execute the encryption
    * *********************** */
    Error = LLF_PKI_RSA_ExecPubKeyExp(pCcPubKey, (CRYS_RSAPrimeData_t *)&KeyGenData_ptr->PrimData);
    if (Error != CRYS_OK)
        goto End;

    /* if the result is the same as the original data set the test as failure */
    if ((DX_PAL_MemCmp(KeyGenData_ptr->PrimData.DataOut, Data_ptr, sizeof(Data_ptr))) == 0) {
        DX_PAL_MemSet(pCcPubKey, 0, sizeof(CRYS_RSAUserPubKey_t));
        DX_PAL_MemSet(pCcPrivKey, 0, sizeof(CRYS_RSAUserPrivKey_t));
#ifndef CRYS_NO_FIPS_SUPPORT
        DX_GLOBAL_FIPS_MODE |= DX_CRYS_FIPS_MODE_ERROR_STATE;
#endif
        Error = CRYS_RSA_KEY_GEN_CONDITIONAL_TEST_FAIL_ERROR;
        goto End;
    }

    /* Clean and fill the data buffer */
    DX_PAL_MemCopy(KeyGenData_ptr->PrimData.DataIn, KeyGenData_ptr->PrimData.DataOut,
                   CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 4);
    DX_PAL_MemSet(KeyGenData_ptr->PrimData.DataOut, 0, CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 4);

    /* Execute the decryption
    * *********************** */
    Error = LLF_PKI_RSA_ExecPrivKeyExp(pCcPrivKey, (CRYS_RSAPrimeData_t *)&KeyGenData_ptr->PrimData);
    if (Error != CRYS_OK)
        return Error;

    /* if the result is not the same as the original data set the test as failure */
    if (DX_PAL_MemCmp(KeyGenData_ptr->PrimData.DataOut, Data_ptr, DataSize)) {
        DX_PAL_MemSet(pCcPubKey, 0, sizeof(CRYS_RSAUserPubKey_t));
        DX_PAL_MemSet(pCcPrivKey, 0, sizeof(CRYS_RSAUserPrivKey_t));
#ifndef CRYS_NO_FIPS_SUPPORT
        DX_GLOBAL_FIPS_MODE |= DX_CRYS_FIPS_MODE_ERROR_STATE;
#endif
        Error = CRYS_RSA_KEY_GEN_CONDITIONAL_TEST_FAIL_ERROR;
        goto End;
    }

    /* Test Passed - return Error = CRYS_OK */

#endif /* CRYS_NO_RSA_SELF_TEST_SUPPORT */

    /* ............... END : Conditional test for Key-Generation ............... */
    /* ------------------------------------------------------------------------- */

    /* ................ set the key valid tags ................................. */
    /* ------------------------------------------------------------------------- */
    pCcUserPrivKey->valid_tag = CRYS_RSA_PRIV_KEY_VALIDATION_TAG;
    pCcUserPubKey->valid_tag  = CRYS_RSA_PUB_KEY_VALIDATION_TAG;

End:

    /* clear the KG data structure */
    DX_PAL_MemSet(KeyGenData_ptr, 0, sizeof(CRYS_RSAKGData_t));
    return Error;

#endif /* !CRYS_NO_HASH_SUPPORT */
#endif /* !CRYS_NO_PKI_SUPPORT */

} /* END OF CRYS_RSA_KG_GenerateKeyPair */

/* ******************************************************************************************** */
/*
   @brief CRYS_RSA_KG_GenerateKeyPairCRT generates a Pair of public and private keys on CRT mode.

   @param[in] PubExp_ptr - The pointer to the public exponent (public key)
   @param[in] PubExpSizeInBytes - The public exponent size in bits.
   @param[in] KeySize  - The size of the key, in bits. Supported sizes are:
                - for PKI without PKA HW: all 256 bit multiples between 512 - 2048;
                - for PKI with PKA: HW all 32 bit multiples between 512 - 2112;
   @param[out] pCcUserPrivKey - A pointer to the private key structure.
               This structure is used as input to the CRYS_RSA_PRIM_Decrypt API.
   @param[out] pCcUserPubKey - A pointer to the public key structure.
               This structure is used as input to the CRYS_RSA_PRIM_Encryped API.
   @param[in] KeyGenData_ptr - a pointer to a structure required for the KeyGen operation.

   @return CRYSError_t - CRYS_OK,
             CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR,
             CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
             CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
             CRYS_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
             CRYS_RSA_INVALID_MODULUS_SIZE,
             CRYS_RSA_INVALID_EXPONENT_SIZE
*/

CEXPORT_C CRYSError_t CRYS_RSA_KG_GenerateKeyPairCRT(uint8_t *PubExp_ptr, uint16_t PubExpSizeInBytes, uint32_t KeySize,
                                                     CRYS_RSAUserPrivKey_t *pCcUserPrivKey,
                                                     CRYS_RSAUserPubKey_t *pCcUserPubKey,
                                                     CRYS_RSAKGData_t *KeyGenData_ptr)
{
    /* LOCAL INITIALIZATIONS AND DECLERATIONS */

    /* the error identifier */
    CRYSError_t Error = CRYS_OK;

    /* the pointers to the key structures */
    CRYSRSAPubKey_t *pCcPubKey;
    CRYSRSAPrivKey_t *pCcPrivKey;
    uint32_t pSizeWords;

    /* FUNCTION LOGIC */

    /* ............... if not supported exit .............................. */
    /* -------------------------------------------------------------------- */

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* ........... checking the validity of the pointer arguments ....... */
    /* ------------------------------------------------------------------ */

    /* ...... checking the key database handle pointer .................. */
    if (PubExp_ptr == DX_NULL)
        return CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR;

    /* ...... checking the validity of the exponent pointer ............. */
    if (pCcUserPrivKey == DX_NULL)
        return CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the modulus pointer .............. */
    if (pCcUserPubKey == DX_NULL)
        return CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the keygen data .................. */
    if (KeyGenData_ptr == DX_NULL)
        return CRYS_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID;

    /* ...... checking the required key size ............................ */
    if ((KeySize < CRYS_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (KeySize >= CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (KeySize % CRYS_RSA_VALID_KEY_SIZE_MULTIPLE_VALUE_IN_BITS)) {
        return CRYS_RSA_INVALID_MODULUS_SIZE;
    }

    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ, PubExp_ptr, PubExpSizeInBytes) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, pCcUserPrivKey, sizeof(CRYS_RSAUserPrivKey_t)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, pCcUserPubKey, sizeof(CRYS_RSAUserPubKey_t)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, KeyGenData_ptr, sizeof(CRYS_RSAKGData_t))) {
        return CRYS_RSA_ILLEGAL_PARAMS_ACCORDING_TO_PRIV_ERROR;
    }

    /* set the public and private key structure pointers */
    pCcPubKey  = (CRYSRSAPubKey_t *)pCcUserPubKey->PublicKeyDbBuff;
    pCcPrivKey = (CRYSRSAPrivKey_t *)pCcUserPrivKey->PrivateKeyDbBuff;

    /* ................ clear all input structures ............................. */
    /* ------------------------------------------------------------------------- */

    DX_PAL_MemSet(pCcUserPrivKey, 0, sizeof(CRYS_RSAUserPrivKey_t));
    DX_PAL_MemSet(pCcUserPubKey, 0, sizeof(CRYS_RSAUserPubKey_t));
    DX_PAL_MemSet(KeyGenData_ptr, 0, sizeof(CRYS_RSAKGData_t));

#ifdef DX_SOFT_KEYGEN
    if (KeySize >= DX_SOFT_KEYGEN_SIZE) {
        Error = CRYS_SW_RSA_KG_GenerateKeyPairCRT((uint8_t *)PubExp_ptr, (uint16_t)PubExpSizeInBytes, (uint32_t)KeySize,
                                                  (SW_CRYS_RSAUserPrivKey_t *)pCcUserPrivKey,
                                                  (SW_CRYS_RSAUserPubKey_t *)pCcUserPubKey,
                                                  (SW_CRYS_RSAKGData_t *)KeyGenData_ptr);

        /* ................ initialize the low level data .............. */
        Error = LLF_PKI_RSA_InitPubKeyDb(pCcPubKey);

        if (Error)
            return Error;

        Error = LLF_PKI_RSA_InitPrivKeyDb(pCcPrivKey);
        return Error;
    }
#endif

    /* ................ loading the public exponent to the structure .......... */
    /* ------------------------------------------------------------------------- */

    /* loading the buffers to start from LS word to MS word */
    Error =
        CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(pCcPubKey->e, sizeof(pCcPubKey->e), PubExp_ptr, PubExpSizeInBytes);
    if (Error != CRYS_OK)
        return Error;

    /* .......... initializing the effective counters size in bits .......... */
    pCcPubKey->eSizeInBits = CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPubKey->e, (PubExpSizeInBytes + 3) / 4);

    /* if the size in bits is 0 - return error */
    if (pCcPubKey->eSizeInBits == 0 || pCcPubKey->eSizeInBits > 17) {
        Error = CRYS_RSA_INVALID_EXPONENT_SIZE;
        goto End;
    }

    /* verifing the exponent has legal value (currently only 0x3,0x11 and 0x10001) */
    /* verifying the exponent has legal value (currently only 0x3,0x11 and 0x10001) */
    if (pCcPubKey->e[0] != CRYS_RSA_KG_PUB_EXP_ALLOW_VAL_1 && pCcPubKey->e[0] != CRYS_RSA_KG_PUB_EXP_ALLOW_VAL_2 &&
        pCcPubKey->e[0] != CRYS_RSA_KG_PUB_EXP_ALLOW_VAL_3) {
        Error = CRYS_RSA_INVALID_EXPONENT_VAL;
        goto End;
    }

    /* .......... initializing the key sizes  ......................... */

    pSizeWords = KeySize / 64;
    /* this initialization is required for the low level function (LLF) - indicates the required
       size of the key to be found */
    pCcPubKey->nSizeInBits  = KeySize;
    pCcPrivKey->nSizeInBits = KeySize;

    /* .......... set the private mode to CRT .................................. */
    /* ------------------------------------------------------------------------- */

    /* set the mode to CRT */
    pCcPrivKey->OperationMode = CRYS_RSA_Crt;

    /* set the key source as internal */
    pCcPrivKey->KeySource = CRYS_RSA_InternalKey;

    /* ................ executing the key generation ........................... */
    /* ------------------------------------------------------------------------- */

    /* ................ generate the prime1 and prime2 random numbers .......... */

    /* generate the random */
    Error = CRYS_RSA_GenerateVectorInRangeX931(pSizeWords, KeyGenData_ptr->KGData.p);
    if (Error != CRYS_OK)
        goto End;

    Error = CRYS_RSA_GenerateVectorInRangeX931(pSizeWords, KeyGenData_ptr->KGData.q);
    if (Error != CRYS_OK)
        goto End;

    /* ................ execute the low level key gen ........................... */
    Error = LLF_PKI_RSA_GenerateKeyPair(pCcPubKey, pCcPrivKey, KeyGenData_ptr);

    /* on failure exit the function */
    if (Error != CRYS_OK)
        goto End;

    /* ................ set the vector sizes ................................... */
    /* ------------------------------------------------------------------------- */

    pCcPrivKey->PriveKeyDb.Crt.PSizeInBits =
        CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPrivKey->PriveKeyDb.Crt.P, (uint16_t)pSizeWords);

    pCcPrivKey->PriveKeyDb.Crt.QSizeInBits =
        CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPrivKey->PriveKeyDb.Crt.Q, (uint16_t)pSizeWords);

    pCcPrivKey->PriveKeyDb.Crt.dPSizeInBits =
        CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPrivKey->PriveKeyDb.Crt.dP, (uint16_t)pSizeWords);

    pCcPrivKey->PriveKeyDb.Crt.dQSizeInBits =
        CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPrivKey->PriveKeyDb.Crt.dQ, (uint16_t)pSizeWords);

    pCcPrivKey->PriveKeyDb.Crt.qInvSizeInBits =
        CRYS_COMMON_GetWordsCounterEffectiveSizeInBits(pCcPrivKey->PriveKeyDb.Crt.qInv, (uint16_t)pSizeWords);

    /* ................ initialize the low level key structures ................ */
    /* ------------------------------------------------------------------------- */

    Error = LLF_PKI_RSA_InitPubKeyDb(pCcPubKey);

    if (Error != CRYS_OK)
        goto End;

    Error = LLF_PKI_RSA_InitPrivKeyDb(pCcPrivKey);

    if (Error != CRYS_OK)
        goto End;

    /* ................ set the key valid tags ................................. */
    /* ------------------------------------------------------------------------- */

    pCcUserPrivKey->valid_tag = CRYS_RSA_PRIV_KEY_VALIDATION_TAG;
    pCcUserPubKey->valid_tag  = CRYS_RSA_PUB_KEY_VALIDATION_TAG;

End:

    /* clear the KG data structure */
    DX_PAL_MemSet(KeyGenData_ptr, 0, sizeof(CRYS_RSAKGData_t));

    return Error;

#endif /* !CRYS_NO_HASH_SUPPORT */
#endif /* !CRYS_NO_PKI_SUPPORT */

} /* END OF CRYS_RSA_KG_GenerateKeyPairCRT */

/* ******************************************************************************************************* */
/*
 * @brief The CRYS_RSA_GenerateVectorInRangeX931 function generates a random vector in range:
 *            MinVect < RandVect < MaxVect, where:
 *            MinVect = sqwRoot(2) * 2^(RndSizeInBits-1),  MaxVect = 2^RndSizeInBits.
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
 *        1.  Calls the CRYS_RND_GenerateVector() function for generating random vector
 *            RndVect of size RndSizeInWords, rounded up to bytes. Set index i
 *            to high word i = SizeInWords-1.
 *        2.  Check and adust candidate for msWord inside the random vector
 *            starting from msWord himselv, if msWord > high word of MinVect,
 *            goto step 3, else try next word i--; if no words to try, then goto
 *            step 1.
 *        3.  Set the found msWord to high position in array and generate new
 *            random words instead all checked and rejected words.
 *
 * @rndSizeWords[in]  - The size of random vectore that is required.
 * @rnd_ptr[out]      - The output buffer of size not less, than rndSizeWords.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                       value MODULE_* as defined in ...
 */
CRYSError_t CRYS_RSA_GenerateVectorInRangeX931(uint32_t rndSizeWords, uint32_t *rnd_ptr)
{
/* MIN_WORD = rounded up MS word of (2^(32*rndSizeWords-1))*sqwRoot(2) */
#define MIN_VAL 0xB504F334

    /* FUNCTION DECLARATIONS */

    CRYSError_t error = CRYS_OK;
    uint32_t msWord;
    int32_t i;
    DxBool_t isFound = DX_FALSE;

#ifdef CRYS_NO_PKI_SUPPORT
    /* prevent compiler warnings */
    rndSizeWords = rndSizeWords;
    rnd_ptr      = rnd_ptr;
#else

    /* FUNCTION LOGIC */

    /* .........         Rnd generation       .............. */
    /* ----------------------------------------------------- */

    while (1) {
        /* Genrate random vector candidate */
        error = CRYS_RND_GenerateVector((uint16_t)rndSizeWords * sizeof(uint32_t), (uint8_t *)rnd_ptr);
        if (error)
            goto End;

        /* Find and adust candidate for msWord inside the random *
         *  vector starting from msWord himselv           */

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
                error = CRYS_RND_GenerateVector((uint16_t)(rndSizeWords - 1 - i) * sizeof(uint32_t),
                                                (uint8_t *)&rnd_ptr[i]);

                if (error)
                    goto End;
            }

            if (isFound == 1)
                break;
        }

        if (isFound) {
            rnd_ptr[0] |= 1UL; /* ensure odd result */
            break;
        }
    }
#endif

End:
    return error;

} /* End of CRYS_RSA_GenerateVectorInRangeX931 */

#endif /* _INTERNAL_CRYS_NO_RSA_KG_SUPPORT */
