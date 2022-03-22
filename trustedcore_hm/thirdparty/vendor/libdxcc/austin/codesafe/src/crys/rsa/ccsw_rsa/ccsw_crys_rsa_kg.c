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
#include "crys_common.h"
#include "crys_common_math.h"
#include "crys_rnd.h"
#include "crys_rnd_local.h"
#include "crys_rsa_error.h"
#include "crys_rsa_local.h"
#include "sw_llf_pki_rsa.h"
#include "ccsw_crys_rsa_types.h"

/* *********************** Defines **************************** */

/* canceling the lint warning:
   Use of goto is deprecated */


/* *********************** Enums ********************************** */

/* *********************** Typedefs ******************************* */

/* *********************** Global Data **************************** */

/*
 For debugging the RSA_KG module define the following flags in project properties
 and perform the following:
   1. Compile project in DEBUG=1 mode.
   2. Define LLF_PKI_PKA_DEBUG.
   3. For findingthe bad random factors (P,Q,P1pR,P2pR,P1qR,P2qR):
      define RSA_KG_FIND_BAD_RND flag, perform test and save (from memory)
      the found bad vectors.
   4. For repeat the testing of found bad vectors, write they as HW
      initialization of the following buffers:
      P=>RSA_KG_debugPvect, Q=>RSA_KG_debugQvect - in the CRYS_RSA_KG.c
      file, and P1pR=>rBuff1, P2pR=>rBuff1, P1qR=>rBuff3, P2qR=>rBuff4 in the
      LLF_PKI_GenKeyX931FindPrime.c file. Define the flag RSA_KG_NO_RND instead
      previously defined RSA_KG_FIND_BAD_RND flag and perform the test.
   5. For ordinary ATP or other tests (without debug) undef all the named flags.
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

   @param [in] PubExp_ptr - The pointer to the public exponent (public key)
   @param [in] PubExpSizeInBytes - The public exponent size in bytes.
   @param [in] KeySize  - The size of the key, in bits. Supported sizes are:
                - for PKI without PKA HW: all 256 bit multiples between 512 - 2048;
                - for PKI with PKA: HW all 32 bit multiples between 512 - 2112;
   @param [out] UserPrivKey_ptr - A pointer to the private key structure.
               This structure is used as input to the CRYS_RSA_PRIM_Decrypt API.
   @param [out] UserPubKey_ptr - A pointer to the public key structure.
               This structure is used as input to the CRYS_RSA_PRIM_Encrypt API.
   @param [in] KeyGenData_ptr - a pointer to a structure required for the KeyGen
      operation.
 * @param RndGenerateVectFunc - The pointer to actual working RND Generate
 *                    vector function given by the user (External or
 *                    CRYS function SW_CRYS_RND_GenerateVector).
 * @param rndCtx_ptr - The pointer to structure, containing context ID and void
 *              pointer to RND State structure, which should be converted to
 *              actual type inside of the function according to used platform
 *                  (External or CRYS).

   @return CRYSError_t - CRYS_OK,
             CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR,
             CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
             CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
             CRYS_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
             CRYS_RSA_INVALID_MODULUS_SIZE,
             CRYS_RSA_INVALID_EXPONENT_SIZE
*/
CEXPORT_C CRYSError_t CRYS_SW_RSA_KG_GenerateKeyPair(uint8_t *PubExp_ptr, uint16_t PubExpSizeInBytes, uint32_t KeySize,
                                                     SW_CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                                                     SW_CRYS_RSAUserPubKey_t *UserPubKey_ptr,
                                                     SW_CRYS_RSAKGData_t *KeyGenData_ptr)
{
    /* LOCAL INITIALIZATIONS AND DECLERATIONS */

    /* the error identifier */
    CRYSError_t Error;

    /* the pointers to the key structures */
    SW_CRYSRSAPubKey_t *PubKey_ptr;
    SW_CRYSRSAPrivKey_t *PrivKey_ptr;

    /* a temp definition to solve a problem on release mode on VC++ */
    volatile uint32_t dummy = PubExpSizeInBytes;

    uint32_t KeySizeInWords = KeySize / 32;

#ifndef CRYS_NO_RSA_SELF_TEST_SUPPORT
    /* Data for Conditional test, after Key - Generation */
    const uint8_t Data_ptr[] = { 'D', 'i', 's', 'c', 'r', 'e', 't', 'i', 'x' };
    uint16_t DataSize        = sizeof(Data_ptr);
#endif

    /* FUNCTION LOGIC */
    /* ............... if not supported exit .............................. */
#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* ................ initializaions and local declarations ............ */
    /* ------------------------------------------------------------------- */

    /* to avoid compilers warnings */
    dummy = dummy;

    /* initialize the error identifier to O.K */
    Error = CRYS_OK;

    /* ................. checking the validity of the pointer arguments ....... */
    /* ------------------------------------------------------------------------ */

    /* ...... checking the key database handle pointer .................... */
    if (PubExp_ptr == NULL)
        return CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR;

    /* ...... checking the validity of the exponent pointer ............... */
    if (UserPrivKey_ptr == NULL)
        return CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the modulus pointer .............. */
    if (UserPubKey_ptr == NULL)
        return CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the keygen data .................. */
    if (KeyGenData_ptr == NULL)
        return CRYS_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID;

    /* ...... checking the exponent size .................. */
    if (PubExpSizeInBytes > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
        return CRYS_RSA_INVALID_EXPONENT_SIZE;

    /* ...... checking the required key size ............................ */
    if ((KeySize < CRYS_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (KeySize > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (KeySize % CRYS_RSA_VALID_KEY_SIZE_MULTIPLE_VALUE_IN_BITS)) {
        return CRYS_RSA_INVALID_MODULUS_SIZE;
    }

    /* set the public and private key structure pointers */
    PubKey_ptr  = (SW_CRYSRSAPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;
    PrivKey_ptr = (SW_CRYSRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

    DX_PAL_MemSet(UserPrivKey_ptr, 0, sizeof(SW_CRYS_RSAUserPrivKey_t));
    DX_PAL_MemSet(UserPubKey_ptr, 0, sizeof(SW_CRYS_RSAUserPubKey_t));
    DX_PAL_MemSet(KeyGenData_ptr, 0, sizeof(SW_CRYS_RSAKGData_t));

    /* ................ loading the public exponent to the structure .......... */
    /* ------------------------------------------------------------------------- */
    /* loading the buffers to start from LS word to MS word */
    CRYS_COMMON_ReverseMemcpy((uint8_t *)PubKey_ptr->e, PubExp_ptr, PubExpSizeInBytes);
    /* .......... initializing the effective counters size in bits .......... */
    PubKey_ptr->eSizeInBits =
        CRYS_COMMON_GetBytesCounterEffectiveSizeInBits((uint8_t *)PubKey_ptr->e, PubExpSizeInBytes);

    /* if the size in bits is 0 - return error */
    if (PubKey_ptr->eSizeInBits == 0) {
        Error = CRYS_RSA_INVALID_EXPONENT_SIZE;
        goto End;
    }

    /* verifying the exponent has legal value (currently only 0x3,0x11 and 0x10001) */
    if (PubKey_ptr->e[0] != 0x3 && PubKey_ptr->e[0] != 0x11 && PubKey_ptr->e[0] != 0x010001) {
        Error = CRYS_RSA_INVALID_EXPONENT_VAL;
        goto End;
    }
    /* .......... initialize the public key on the private structure ............... */
    DX_PAL_MemCopy(PrivKey_ptr->PriveKeyDb.NonCrt.e, PubKey_ptr->e, 4 * ((PubExpSizeInBytes + 3) / 4));
    PrivKey_ptr->PriveKeyDb.NonCrt.eSizeInBits = PubKey_ptr->eSizeInBits;

    /* .......... initializing the key size in bits ......................... */

    /* this initialization is required for the low level function (LLF) - indicates the required
       size of the key to be found */
    PubKey_ptr->nSizeInBits  = KeySize;
    PrivKey_ptr->nSizeInBits = KeySize;

    /* .......... set the private mode to non CRT .............................. */
    /* ------------------------------------------------------------------------- */

    /* set the mode to non CRT */
    PrivKey_ptr->OperationMode = CRYS_RSA_NoCrt;

    /* set the key source as internal */
    PrivKey_ptr->KeySource = CRYS_RSA_InternalKey;

    /* ................ executing the key generation ........................... */
    /* ------------------------------------------------------------------------- */
    /* generate the random */

#if ((!defined RSA_KG_FIND_BAD_RND && !defined RSA_KG_NO_RND) || defined RSA_KG_FIND_BAD_RND || !defined DEBUG)
    Error = CRYS_RSA_GenerateVectorInRangeX931(KeySizeInWords / 2, KeyGenData_ptr->KGData.p);

    if (Error != CRYS_OK)
        goto End;

    Error = CRYS_RSA_GenerateVectorInRangeX931(KeySizeInWords / 2, KeyGenData_ptr->KGData.q);

    if (Error != CRYS_OK)
        goto End;
#endif

#if (defined RSA_KG_FIND_BAD_RND && defined DEBUG)
    DX_PAL_MemCopy(RSA_KG_debugPvect, (uint8_t *)KeyGenData_ptr->KGData.p, KeySizeInBytes / 2);
    DX_PAL_MemCopy(RSA_KG_debugQvect, (uint8_t *)KeyGenData_ptr->KGData.q, KeySizeInBytes / 2);
#endif

#if (defined RSA_KG_NO_RND && defined DEBUG)
    DX_PAL_MemCopy((uint8_t *)KeyGenData_ptr->KGData.p, RSA_KG_debugPvect, KeySizeInBytes / 2);
    DX_PAL_MemCopy((uint8_t *)KeyGenData_ptr->KGData.q, RSA_KG_debugQvect, KeySizeInBytes / 2);
#endif

#if ((defined RSA_KG_FIND_BAD_RND || defined RSA_KG_NO_RND) && defined DEBUG)
#ifdef BIG__ENDIAN
    /* for big endiannes machine reverse bytes order in words according to Big Endian  */
    CRYS_COMMON_INVERSE_UINT32_IN_ARRAY(KeyGenData_ptr->KGData.p, KeySizeInWords / 2);
    CRYS_COMMON_INVERSE_UINT32_IN_ARRAY(KeyGenData_ptr->KGData.q, KeySizeInWords / 2);
#endif
#endif
    /* clean the n-buffer */
    DX_PAL_MemSetZero(PrivKey_ptr->n, 4 * CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS);

    /* ................ execute the low level keygen ........................... */
    Error = SW_LLF_PKI_RSA_GenerateKeyPair(PubKey_ptr, PrivKey_ptr, KeyGenData_ptr);

    /* on failure exit the function */
    if (Error != CRYS_OK)

        goto End;

    /* ................ initialize the low level key structures ................ */
    /* ------------------------------------------------------------------------- */
    Error = SW_LLF_PKI_RSA_InitPubKeyDb(PubKey_ptr);

    if (Error != CRYS_OK)

        goto End;
    Error = SW_LLF_PKI_RSA_InitPrivKeyDb(PrivKey_ptr);

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
    Error = SW_LLF_PKI_RSA_ExecPubKeyExp(PubKey_ptr, (CRYS_RSAPrimeData_t *)&KeyGenData_ptr->PrimData);
    if (Error != CRYS_OK) {
        goto End;
    }
    /* if the result is the same as the original data set the test as failure */
    if ((DX_PAL_MemCmp(KeyGenData_ptr->PrimData.DataOut, Data_ptr, sizeof(Data_ptr))) == 0) {
        DX_PAL_MemSet(PubKey_ptr, 0, sizeof(SW_CRYS_RSAUserPubKey_t));
        DX_PAL_MemSet(PrivKey_ptr, 0, sizeof(SW_CRYS_RSAUserPrivKey_t));
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
    Error = SW_LLF_PKI_RSA_ExecPrivKeyExp(PrivKey_ptr, (SW_CRYS_RSAPrimeData_t *)&KeyGenData_ptr->PrimData);
    if (Error != CRYS_OK) {
        return Error;
    }
    /* if the result is not the same as the original data set the test as failure */
    if (DX_PAL_MemCmp(KeyGenData_ptr->PrimData.DataOut, Data_ptr, DataSize)) {
        DX_PAL_MemSet(PubKey_ptr, 0, sizeof(SW_CRYS_RSAUserPubKey_t));
        DX_PAL_MemSet(PrivKey_ptr, 0, sizeof(SW_CRYS_RSAUserPrivKey_t));
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
    UserPrivKey_ptr->valid_tag = CRYS_RSA_PRIV_KEY_VALIDATION_TAG;
    UserPubKey_ptr->valid_tag  = CRYS_RSA_PUB_KEY_VALIDATION_TAG;
End:
    /* clear the KG data structure */
    DX_PAL_MemSet(KeyGenData_ptr, 0, sizeof(SW_CRYS_RSAKGData_t));
    return Error;

#endif /* !CRYS_NO_HASH_SUPPORT */
#endif /* !CRYS_NO_PKI_SUPPORT */

} /* END OF CRYS_SWRSA_KG_GenerateKeyPair */

/* ******************************************************************************************** */
/*
   @brief CRYS_SWRSA_KG_GenerateKeyPairCRT generates a Pair of public and private keys on CRT mode.

   @param [in] PubExp_ptr - The pointer to the public exponent (public key)
   @param [in] PubExpSizeInBytes - The public exponent size in bits.
   @param [in] KeySize  - The size of the key, in bits. Supported sizes are:
                - for PKI without PKA HW: all 256 bit multiples between 512 - 2048;
                - for PKI with PKA: HW all 32 bit multiples between 512 - 2112;
   @param [out] UserPrivKey_ptr - A pointer to the private key structure.
               This structure is used as input to the CRYS_RSA_PRIM_Decrypt API.
   @param [out] UserPubKey_ptr - A pointer to the public key structure.
               This structure is used as input to the CRYS_RSA_PRIM_Encryped API.
   @param [in] KeyGenData_ptr - a pointer to a structure required for the KeyGen operation.
 * @param [in] RndGenerateVectFunc - The pointer to actual working RND Generate
 *                    vector function given by the user (External or
 *                    CRYS function SW_CRYS_RND_GenerateVector).
 * @param [in/out] RndCtx_ptr - The pointer to structure, containing context ID and void
 *              pointer to RND State structure, which should be converted to
 *              actual type inside of the function according to used platform
 *                  (External or CRYS).

   @return CRYSError_t - CRYS_OK,
             CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR,
             CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
             CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR,
             CRYS_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID,
             CRYS_RSA_INVALID_MODULUS_SIZE,
             CRYS_RSA_INVALID_EXPONENT_SIZE
*/

CEXPORT_C CRYSError_t CRYS_SW_RSA_KG_GenerateKeyPairCRT(uint8_t *PubExp_ptr, uint16_t PubExpSizeInBytes,
                                                        uint32_t KeySize, SW_CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                                                        SW_CRYS_RSAUserPubKey_t *UserPubKey_ptr,
                                                        SW_CRYS_RSAKGData_t *KeyGenData_ptr)
{
    /* LOCAL INITIALIZATIONS AND DECLERATIONS */

    /* the error identifier */
    CRYSError_t Error = CRYS_OK;

    /* the pointers to the key structures */
    SW_CRYSRSAPubKey_t *PubKey_ptr;
    SW_CRYSRSAPrivKey_t *PrivKey_ptr;

    /* FUNCTION LOGIC */
    uint32_t KeySizeInBytes = KeySize / 8;
    uint32_t KeySizeInWords = KeySize / 32;

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* ................ initializations and local declarations ............ */
    /* ------------------------------------------------------------------- */

    /* ................. checking the validity of the pointer arguments ....... */
    /* ------------------------------------------------------------------------ */
    /* ...... checking the key database handle pointer .................... */
    if (PubExp_ptr == NULL)
        return CRYS_RSA_INVALID_EXPONENT_POINTER_ERROR;

    /* ...... checking the validity of the exponent pointer ............... */
    if (UserPrivKey_ptr == NULL)
        return CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the modulus pointer .............. */
    if (UserPubKey_ptr == NULL)
        return CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

    /* ...... checking the validity of the keygen data .................. */
    if (KeyGenData_ptr == NULL)
        return CRYS_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID;

    /* ...... checking the required key size ............................ */
    if ((KeySize < CRYS_RSA_MIN_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (KeySize > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS) ||
        (KeySize % CRYS_RSA_VALID_KEY_SIZE_MULTIPLE_VALUE_IN_BITS))
        return CRYS_RSA_INVALID_MODULUS_SIZE;

    if (PubExpSizeInBytes > CRYS_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES)
        return CRYS_RSA_INVALID_EXPONENT_SIZE;

    /* set the public and private key structure pointers */
    PubKey_ptr  = (SW_CRYSRSAPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;
    PrivKey_ptr = (SW_CRYSRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

    /* ................ clear all input structures ............................. */
    /* ------------------------------------------------------------------------- */

    DX_PAL_MemSet(UserPrivKey_ptr, 0, sizeof(SW_CRYS_RSAUserPrivKey_t));
    DX_PAL_MemSet(UserPubKey_ptr, 0, sizeof(SW_CRYS_RSAUserPubKey_t));
    DX_PAL_MemSet(KeyGenData_ptr, 0, sizeof(SW_CRYS_RSAKGData_t));

    /* ................ loading the public exponent to the structure .......... */
    /* ------------------------------------------------------------------------- */

    /* loading the buffers to start from LS word to MS word */
    CRYS_COMMON_ReverseMemcpy((uint8_t *)PubKey_ptr->e, PubExp_ptr, PubExpSizeInBytes);

    /* .......... initializing the effective counters size in bits .......... */
    PubKey_ptr->eSizeInBits =
        CRYS_COMMON_GetBytesCounterEffectiveSizeInBits((uint8_t *)PubKey_ptr->e, PubExpSizeInBytes);

    /* if the size in bits is 0 - return error */
    if (PubKey_ptr->eSizeInBits == 0) {
        Error = CRYS_RSA_INVALID_EXPONENT_SIZE;
        goto End;
    }

    /* verifing the exponent has legal value (currently only 0x3,0x11 and 0x10001) */
    switch (PubKey_ptr->eSizeInBits) {
    case 2:
        if (PubKey_ptr->e[0] != 0x3) {
            Error = CRYS_RSA_INVALID_EXPONENT_VAL;
            goto End;
        }
        break;
    case 5:
        if (PubKey_ptr->e[0] != 0x11) {
            Error = CRYS_RSA_INVALID_EXPONENT_VAL;
            goto End;
        }
        break;
    case 17:
        if (PubKey_ptr->e[0] != 0x010001) {
            Error = CRYS_RSA_INVALID_EXPONENT_VAL;
            goto End;
        }
        break;
    default:
        Error = CRYS_RSA_INVALID_EXPONENT_SIZE;
        goto End;
    }
    /* .......... initializing the key size in bits ......................... */

    /* this initialization is required for the low level function (LLF) - indicates the required
       size of the key to be found */
    PubKey_ptr->nSizeInBits  = KeySize;
    PrivKey_ptr->nSizeInBits = KeySize;

    /* .......... set the private mode to CRT .................................. */
    /* ------------------------------------------------------------------------- */

    /* set the mode to CRT */
    PrivKey_ptr->OperationMode = CRYS_RSA_Crt;

    /* set the key source as internal */
    PrivKey_ptr->KeySource = CRYS_RSA_InternalKey;

    /* ................ executing the key generation ........................... */
    /* ------------------------------------------------------------------------- */

    /* ................ generate the prime1 and prime2 random numbers .......... */

    /* generate the random */
    Error = CRYS_RSA_GenerateVectorInRangeX931(KeySizeInWords / 2, KeyGenData_ptr->KGData.p);

    if (Error != CRYS_OK)
        goto End;

    Error = CRYS_RSA_GenerateVectorInRangeX931(KeySizeInWords / 2, KeyGenData_ptr->KGData.q);

    if (Error != CRYS_OK)
        goto End;

#ifdef BIG__ENDIAN
    /* for big endianness machine reverse bytes order according to Big Endian words */
    CRYS_COMMON_INVERSE_UINT32_IN_ARRAY(KeyGenData_ptr->KGData.p, KeySizeInWords / 2);
    CRYS_COMMON_INVERSE_UINT32_IN_ARRAY(KeyGenData_ptr->KGData.q, KeySizeInWords / 2);
#endif

    /* clean the n-buffer */
    DX_PAL_MemSetZero(PrivKey_ptr->n, 4 * CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS);

    /* ................ execute the low level key gen ........................... */
    Error = SW_LLF_PKI_RSA_GenerateKeyPair(PubKey_ptr, PrivKey_ptr, KeyGenData_ptr);

    /* on failure exit the function */
    if (Error != CRYS_OK)
        goto End;

    /* ................ set the vector sizes ................................... */
    /* ------------------------------------------------------------------------- */

    PrivKey_ptr->PriveKeyDb.Crt.PSizeInBits =
        CRYS_COMMON_GetBytesCounterEffectiveSizeInBits((uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.P, KeySizeInBytes / 2);

    PrivKey_ptr->PriveKeyDb.Crt.QSizeInBits =
        CRYS_COMMON_GetBytesCounterEffectiveSizeInBits((uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.Q, KeySizeInBytes / 2);

    PrivKey_ptr->PriveKeyDb.Crt.dPSizeInBits =
        CRYS_COMMON_GetBytesCounterEffectiveSizeInBits((uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.dP, KeySizeInBytes / 2);

    PrivKey_ptr->PriveKeyDb.Crt.dQSizeInBits =
        CRYS_COMMON_GetBytesCounterEffectiveSizeInBits((uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.dQ, KeySizeInBytes / 2);

    PrivKey_ptr->PriveKeyDb.Crt.qInvSizeInBits =
        CRYS_COMMON_GetBytesCounterEffectiveSizeInBits((uint8_t *)PrivKey_ptr->PriveKeyDb.Crt.qInv, KeySizeInBytes / 2);

    /* ................ initialize the low level key structures ................ */
    /* ------------------------------------------------------------------------- */

    Error = SW_LLF_PKI_RSA_InitPubKeyDb(PubKey_ptr);

    if (Error != CRYS_OK)
        goto End;

    Error = SW_LLF_PKI_RSA_InitPrivKeyDb(PrivKey_ptr);

    if (Error != CRYS_OK)
        goto End;

    /* ................ set the key valid tags ................................. */
    /* ------------------------------------------------------------------------- */

    UserPrivKey_ptr->valid_tag = CRYS_RSA_PRIV_KEY_VALIDATION_TAG;
    UserPubKey_ptr->valid_tag  = CRYS_RSA_PUB_KEY_VALIDATION_TAG;

End:

    /* clear the KG data structure */
    DX_PAL_MemSet(KeyGenData_ptr, 0, sizeof(SW_CRYS_RSAKGData_t));

    return Error;

#endif /* !CRYS_NO_HASH_SUPPORT */
#endif /* !CRYS_NO_PKI_SUPPORT */

} /* END OF CRYS_RSA_KG_GenerateKeyPairCRT */

#endif /* _INTERNAL_CRYS_NO_RSA_KG_SUPPORT */
