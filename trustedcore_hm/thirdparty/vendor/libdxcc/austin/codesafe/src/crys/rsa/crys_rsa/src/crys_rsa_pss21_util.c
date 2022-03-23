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

/* ----------------------------------------------------------
 *
 * Inculde Files
 *
 * ---------------------------------------------------------- */

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

#ifndef DX_OEM_FW
#include "crys.h"
#else
#include "oem_crys.h"
#endif

#include "dx_pal_mem.h"
#include "crys_common_math.h"
#include "crys_rsa_local.h"
#include "crys_rsa_error.h"
#include "crys_hash.h"

/* canceling the lint warning:
  Use of goto is deprecated */


#if CRYS_RSA_SIGN_USE_TEMP_SALT
#include "CRYS_RSA_PSS21_defines.h"
extern uint8_t SaltDB_T[NUM_OF_SETS_TEST_VECTORS][NUM_OF_TEST_VECTOR_IN_SET][CRYS_RSA_PSS_SALT_LENGTH];
extern uint16_t Global_Set_Index_T;
extern uint16_t Global_vector_Index_T;
#endif

#if !defined(_INTERNAL_CRYS_NO_RSA_SCHEME_21_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_VERIFY_SUPPORT)

/* ******************************************************************************************************* */
/*
    Function Name: CRYS_RSA_PSS_Verify21
    Date:   06-12-2004
    Author:    Ohad Shperling


    \brief CRYS_RSA_PSS_Verify21 implements EMSA-PSS-Verify algorithm
   as defined in PKCS#1 v2.1 Sec 9.1.2

   @param[in] Context_ptr - Pointer to a valid context as
                given from the VerifyFinish function.

   The field HASH_Result inside the Context_ptr is initialized with the Hashed digested message.
   The field HASH_Result_Size inside the Context_ptr is initialized with the Hash digested message size

   @return CRYSError_t - CRYS_OK,
             CRYS_BAD_PARAM, CRYS_OUT_OF_RANGE
*/
CRYSError_t CRYS_RSA_PSS_Verify21(RSAPubContext_t *Context_ptr)
{
    /* *********Fitting to the spec**************************** */
    /* Context_ptr->MsgDigestCAL = mHash = Hash(M)
     * &Context_ptr->KeyObj.PubObj.EBD[0] = pointer to EM = S^E mod N
     * &Context_ptr->KeyObj.PubObj.EBDSize = pointer to EM size
     */

    CRYSError_t Error;
    uint8_t *ED_ptr;
    uint32_t EDSizeInBytes;
    uint32_t PubNNewSizeBytes, i;
    uint8_t *maskedDB_ptr;

    uint32_t maskedDB_size;
    uint32_t TempIndex;
    uint8_t TempByte;
    uint8_t *dbMask_ptr = Context_ptr->T_Buf;

    CRYS_HASH_Result_t H_Saved_buf;
    /* Set the ED block pointer */

    /* Temporary - only for the size of N */
    CRYSRSAPubKey_t *PubKey_ptr = (CRYSRSAPubKey_t *)Context_ptr->PubUserKey.PublicKeyDbBuff;

    /* the hash operation mode for inner hash */
    CRYS_HASH_OperationMode_t HashOperationMode;

    /* FUNCTION LOGIC */

    ED_ptr        = (uint8_t *)&Context_ptr->EBD[0]; /* = EM */
    EDSizeInBytes = Context_ptr->EBDSizeInBits / 8;
    if (Context_ptr->EBDSizeInBits % 8)
        EDSizeInBytes++;

    /* Round up the new bytes number - According to the Spec */
    PubNNewSizeBytes = (PubKey_ptr->nSizeInBits - 1) / 8;

    if (((PubKey_ptr->nSizeInBits - 1) % 8) !=
        0) { /* Rounding Only in case that (PubNSizebits -1) is not divisble by 8 */
        PubNNewSizeBytes++;
    } else { /* (PubNSizebits -1) is divisble by 8 hence ED_ptr has to be shortened by the first octet according to the
                spec */
        ED_ptr += 1;
        EDSizeInBytes -= 1;
    }

    /*
     *  9.1.2 <3> Check restriction of PubNNewSizeBytes - already checked in Verify Init
     */

    /*
     *  9.1.2 <4> Check that the rightmost octet of EM have the hexadecimal value 0xbc
     */
    if (ED_ptr[EDSizeInBytes - 1] != 0xbc)
        return CRYS_RSA_ERROR_PSS_INCONSISTENT_VERIFY;

    /*
     *  9.1.2 <5> Define the H and the maskedDB
     */

    maskedDB_ptr  = ED_ptr;
    maskedDB_size = PubNNewSizeBytes - Context_ptr->HASH_Result_Size * 4 - 1;

    /* need to save H because ED_ptr is to be used - Context_ptr->MsgDigestSRC = H */
    DX_PAL_MemCopy((uint8_t *)H_Saved_buf, &ED_ptr[maskedDB_size], Context_ptr->HASH_Result_Size * 4);

    /*
     *  9.1.2 <6> Check that the leftmost bits in the leftmost octet of EM have the value 0
     */

    TempIndex = 8 * PubNNewSizeBytes - (PubKey_ptr->nSizeInBits - 1);
    /* Note TempIndex is size in bits */
    TempByte = 0x80;
    for (i = 0; i < TempIndex; i++) {
        if (maskedDB_ptr[0] & TempByte)
            return CRYS_RSA_ERROR_PSS_INCONSISTENT_VERIFY;
        TempByte >>= 1;
    }

    /*
     *  9.1.2 <7> Let dbMask = MGF(H,emLen-hLen-1)
     */

    /* Setting the correct hash function mode */
    switch (Context_ptr->RsaHashOperationMode) {
    case CRYS_RSA_HASH_SHA1_mode:
    case CRYS_RSA_After_SHA1_mode:
        HashOperationMode = CRYS_HASH_SHA1_mode;
        break;

    case CRYS_RSA_HASH_SHA224_mode:
    case CRYS_RSA_After_SHA224_mode:
        HashOperationMode = CRYS_HASH_SHA224_mode;
        break;

    case CRYS_RSA_HASH_SHA256_mode:
    case CRYS_RSA_After_SHA256_mode:
        HashOperationMode = CRYS_HASH_SHA256_mode;
        break;

    case CRYS_RSA_HASH_SHA384_mode:
    case CRYS_RSA_After_SHA384_mode:
        HashOperationMode = CRYS_HASH_SHA384_mode;
        break;

    case CRYS_RSA_HASH_SHA512_mode:
    case CRYS_RSA_After_SHA512_mode:
        HashOperationMode = CRYS_HASH_SHA512_mode;
        break;

    case CRYS_RSA_HASH_MD5_mode:
    case CRYS_RSA_After_MD5_mode:
        HashOperationMode = CRYS_HASH_MD5_mode;
        break;

    case CRYS_RSA_HASH_NO_HASH_mode:
    default:
        /* No other Hash functions are operating for now */
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    switch (Context_ptr->MGF_2use) {
    case CRYS_PKCS1_MGF1:

        Error =
            CRYS_RSA_OAEPMGF1((uint16_t)(Context_ptr->HASH_Result_Size * 4), (uint8_t *)H_Saved_buf, /* H */
                              (uint16_t)(Context_ptr->HASH_Result_Size * 4),                         /* H_Size */
                              PubNNewSizeBytes - Context_ptr->HASH_Result_Size * 4 - 1, dbMask_ptr, HashOperationMode,
                              (uint8_t *)Context_ptr->PrimeData.DataOut, (uint8_t *)Context_ptr->PrimeData.DataIn);
        if (Error != CRYS_OK) {
            return Error;
        }

        break;

        /* Currently for PKCS1 Ver 2.1 only MGF1 is implemented */
    case CRYS_PKCS1_NO_MGF:
    default:

        return CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;

    } /* end of MGF type switch case */

    /*
     *  9.1.2 <8> Xor operation on length (PubNNewSizeBytes - Context_ptr->hLen - 1)
     */

    for (i = 0; i < maskedDB_size; i++) {
        dbMask_ptr[i] = dbMask_ptr[i] ^ maskedDB_ptr[i];
    }

    /*
     *  9.1.2 <9> Set the leftmost 8emLen - emBits bits of the leftmost octet in DB to zero
     */

    TempIndex = 8 * PubNNewSizeBytes - (PubKey_ptr->nSizeInBits - 1);
    /* Note TempIndex is size in bits */
    TempByte = 0x7F;
    for (i = 0; i < TempIndex; i++) {
        dbMask_ptr[0] &= TempByte;
        TempByte >>= 1;
    }

    /*
     *  9.1.2 <10>
     */

    if (Context_ptr->SaltLen == CRYS_RSA_VERIFY_SALT_LENGTH_UNKNOWN) {
        i = 0;
        while (dbMask_ptr[i] == 0)
            i++;
    } else {
        TempIndex = PubNNewSizeBytes - Context_ptr->HASH_Result_Size * 4 - Context_ptr->SaltLen - 2;
        for (i = 0; i < TempIndex; i++) {
            if (dbMask_ptr[i] != 0)
                return CRYS_RSA_ERROR_PSS_INCONSISTENT_VERIFY;
        }
    }

    if (dbMask_ptr[i] != 0x01)
        return CRYS_RSA_ERROR_PSS_INCONSISTENT_VERIFY;

    /* Derive the salt length if not supported */
    if (Context_ptr->SaltLen == CRYS_RSA_VERIFY_SALT_LENGTH_UNKNOWN) {
        Context_ptr->SaltLen = (uint16_t)(PubNNewSizeBytes - Context_ptr->HASH_Result_Size * 4 - 2 - i);
    }

    /*
     *  9.1.2 <11> Let salt be the last sLen octets in DB
     */

    /*
     *  9.1.2 <12> Let M' ==>
     *     (0x) 00 00 00 00 00 00 00 00 || mHash || salt
     */

    DX_PAL_MemSet(ED_ptr, 0x00, CRYS_RSA_PSS_PAD1_LEN); /* DX_CRYS_RSA_PSS_PAD1_LEN = 8 */

    /* copy the Hash output */
    DX_PAL_MemCopy(&ED_ptr[CRYS_RSA_PSS_PAD1_LEN], (uint8_t *)Context_ptr->HASH_Result,
                   Context_ptr->HASH_Result_Size * 4);
    DX_PAL_MemCopy(&ED_ptr[CRYS_RSA_PSS_PAD1_LEN + Context_ptr->HASH_Result_Size * 4],
                   &dbMask_ptr[maskedDB_size - Context_ptr->SaltLen], Context_ptr->SaltLen);

    /*
     *  9.1.2 <13> H' = Hash(M')
     */

    Error = CRYS_HASH(HashOperationMode, ED_ptr,
                      CRYS_RSA_PSS_PAD1_LEN + Context_ptr->HASH_Result_Size * 4 + Context_ptr->SaltLen, /* 8+20+20 */
                      Context_ptr->HASH_Result);

    if (Error != CRYS_OK) {
        return Error;
    }

    if (DX_PAL_MemCmp((uint8_t *)Context_ptr->HASH_Result, (uint8_t *)H_Saved_buf, Context_ptr->HASH_Result_Size * 4)) {
        return CRYS_RSA_ERROR_PSS_INCONSISTENT_VERIFY;
    } else {
        return CRYS_OK;
    }
}

#endif /* !defined(_INTERNAL_CRYS_NO_RSA_SCHEME_21_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_VERIFY_SUPPORT) */

#if !defined(_INTERNAL_CRYS_NO_RSA_SCHEME_21_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_SIGN_SUPPORT)
#ifndef _INTERNAL_CRYS_NO_RSA_SIGN_SUPPORT
/* -------------------------------------------------------------
 *    Function Name: CRYS_RSA_PSS_Sign21
 *    Date:   06-12-2004
 *    Author:    Ohad Shperling
 *
 *    Inputs:
 *
 *    Outputs:
 *
 *    Algorithm: According to PKCS1 v.2.1
 *
 *
 *    Update History:
 *    Date:        Description:
 *
 * ----------------------------------------------------------- */

CRYSError_t CRYS_RSA_PSS_Sign21(RSAPrivContext_t *Context_ptr, uint8_t *Output_ptr)
{
#if CRYS_RSA_SIGN_USE_TEMP_SALT
    /* only for debug of signing */
    /* Using a known Salt for debug */
    uint8_t *Salt = SaltDB_T[Global_Set_Index_T][Global_vector_Index_T];
#else
    /* In operational mode Salt is a random number */
    uint8_t *Salt =
        Output_ptr; /* This stack memory saving is ok because Output_ptr is used only in the Primitive operation */
#endif

    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;
    uint32_t i;
    uint32_t TempIndex;

    /* Parameter for the actual size of the modulus N in bits */
    uint32_t PrvNSizebits;

    /* Parameter for the new size of the modulus N in bytes according to PKCS1 Ver 2.1 */
    uint32_t PrvNNewSizeBytes; /* rounded number of Bytes for padding2 length */
    uint32_t Index4PSLength;

    uint8_t *EMPadOutputBuffer;
    uint8_t *MaskOutput_ptr = Context_ptr->T_Buf; /* for stack space saving */

    /* Parameter for bitwise operation on one Byte */
    uint8_t TempByte;

    CRYSRSAPrivKey_t *PrivKey_ptr = (CRYSRSAPrivKey_t *)Context_ptr->PrivUserKey.PrivateKeyDbBuff;

    /* the hash operation mode for inner hash */
    CRYS_HASH_OperationMode_t HashOperationMode;

    /* FUNCTION LOGIC */

    /* .................. initializing local variables ................... */
    /* ------------------------------------------------------------------- */

    EMPadOutputBuffer = (uint8_t *)Context_ptr->EBD;

    /*
     * ? 9.1.1 <1> checking length restriction of the message M - done in the Update phase
     */

    /*
     *  9.1.1 <2> Hash operation - done in the Update phase
     */

    /*
     *    Finding Actual size in bits and new size of Bytes of the modulus N
     *    This value is already calculated in
     *    Context_ptr->KeyObj.PrvCRTObj.nSizeInBits   or in
     *    Context_ptr->KeyObj.PrvPAIRObj.nSizeInBits
     */

    /* Reset the working buffer */
    DX_PAL_MemSet(EMPadOutputBuffer, 0x00, CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 4);

    /* Round up the new bytes number */
    PrvNNewSizeBytes = (PrivKey_ptr->nSizeInBits - 1) / 8;
    PrvNSizebits     = PrivKey_ptr->nSizeInBits;

    if (((PrvNSizebits - 1) % 8) != 0)
        PrvNNewSizeBytes++;
    /* rounding */

    /*
     *  9.1.1 <3> Check restriction of PrvNNewSizeBytes - already checked in Sign Init
     */

    /*
     *  9.1.1 <5> Generating M' ==> using the output buffer as a container
     *    EMPadOutputBuffer = (0x) 00 00 00 00 00 00 00 00 || mHash || salt
     */

    DX_PAL_MemSet(EMPadOutputBuffer, 0x00, CRYS_RSA_PSS_PAD1_LEN); /* DX_CRYS_RSA_PSS_PAD1_LEN = 8 */

    /* copy the Hash output */
    DX_PAL_MemCopy(&EMPadOutputBuffer[CRYS_RSA_PSS_PAD1_LEN], (uint8_t *)Context_ptr->HASH_Result,
                   Context_ptr->HASH_Result_Size * 4);

/*
 *  9.1.1 <4> Generating a random salt ==> using the output buffer as a container
 */
#if !CRYS_RSA_SIGN_USE_TEMP_SALT /* If not using a known salt for Debug then generate random */
    Error = CRYS_RND_GenerateVector(Context_ptr->SaltLen, Salt);
    if (Error != CRYS_OK) {
        return Error;
    }
#endif

    DX_PAL_MemCopy(&EMPadOutputBuffer[CRYS_RSA_PSS_PAD1_LEN + Context_ptr->HASH_Result_Size * 4], Salt,
                   Context_ptr->SaltLen);

    /*
     *  9.1.1 <6> Hash(M')
     */

    /* Setting the correct hash function mode */
    switch (Context_ptr->RsaHashOperationMode) {
    case CRYS_RSA_HASH_SHA1_mode:
    case CRYS_RSA_After_SHA1_mode:
        HashOperationMode = CRYS_HASH_SHA1_mode;
        break;

    case CRYS_RSA_HASH_SHA224_mode:
    case CRYS_RSA_After_SHA224_mode:
        HashOperationMode = CRYS_HASH_SHA224_mode;
        break;

    case CRYS_RSA_HASH_SHA256_mode:
    case CRYS_RSA_After_SHA256_mode:
        HashOperationMode = CRYS_HASH_SHA256_mode;
        break;

    case CRYS_RSA_HASH_SHA384_mode:
    case CRYS_RSA_After_SHA384_mode:
        HashOperationMode = CRYS_HASH_SHA384_mode;
        break;

    case CRYS_RSA_HASH_SHA512_mode:
    case CRYS_RSA_After_SHA512_mode:
        HashOperationMode = CRYS_HASH_SHA512_mode;
        break;

    case CRYS_RSA_HASH_MD5_mode:
    case CRYS_RSA_After_MD5_mode:
        HashOperationMode = CRYS_HASH_MD5_mode;
        break;

    case CRYS_RSA_HASH_NO_HASH_mode:
    default:
        /* No other Hash functions are operating for now */
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    Error = CRYS_HASH(HashOperationMode, EMPadOutputBuffer,
                      CRYS_RSA_PSS_PAD1_LEN + Context_ptr->HASH_Result_Size * 4 + Context_ptr->SaltLen, /* 8+hLen+20 */
                      Context_ptr->HASH_Result);

    if (Error != CRYS_OK) {
        return Error;
    }

    /*
     *  9.1.1 <7+8> Generate an octet string of zeros of size emLen-sLen-hLen-2 ==> use the output buffer as a container
     *                DB = PS || 0x01 || salt
     */

    Index4PSLength = PrvNNewSizeBytes - Context_ptr->SaltLen - Context_ptr->HASH_Result_Size * 4 - 2;

    DX_PAL_MemSet(EMPadOutputBuffer, 0x00, Index4PSLength);
    EMPadOutputBuffer[Index4PSLength] = 0x01;
    DX_PAL_MemCopy(&(EMPadOutputBuffer[Index4PSLength + 1]), Salt, Context_ptr->SaltLen);

    /*
     *  9.1.1 <9> MGF operation
     */

    switch (Context_ptr->MGF_2use) {
    case CRYS_PKCS1_MGF1:

        Error = CRYS_RSA_OAEPMGF1((uint16_t)(Context_ptr->HASH_Result_Size * 4), (uint8_t *)Context_ptr->HASH_Result,
                                  (uint16_t)(Context_ptr->HASH_Result_Size * 4),
                                  PrvNNewSizeBytes - Context_ptr->HASH_Result_Size * 4 - 1, MaskOutput_ptr,
                                  HashOperationMode, (uint8_t *)Context_ptr->PrimeData.DataOut,
                                  (uint8_t *)Context_ptr->PrimeData.DataIn);
        if (Error != CRYS_OK) {
            return Error;
        }

        break;

        /* Currently for PKCS1 Ver 2.1 only MGF1 is implemented */
    case CRYS_PKCS1_NO_MGF:

    default:

        return CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;

    } /* end of MGF type switch case */

    /*
     *  9.1.1 <10> Xor operation on length (PrvNNewSizeBytes - Context_ptr->hLen - 1)
     */

    TempIndex = PrvNNewSizeBytes - Context_ptr->HASH_Result_Size * 4 - 1;
    for (i = 0; i < TempIndex; i++) {
        EMPadOutputBuffer[i] = EMPadOutputBuffer[i] ^ *(MaskOutput_ptr + i);
    }

    /*
     *  ? 9.1.1 <11> Set the leftmost 8*emLen-emBits bits of the leftmost octet in maskedDB to zero
     *        By convention the pointer is pointing to the leftmost Octet which is the most significant octet
     */

    TempIndex = 8 * PrvNNewSizeBytes - (PrvNSizebits - 1);

    /* Note TempIndex is size in bits */
    TempByte = 0x7F;
    for (i = 0; i < TempIndex; i++) {
        EMPadOutputBuffer[0] &= TempByte;
        TempByte >>= 1;
    }

    /*
     *  ? 9.1.1 <12> Let EM = maskedDB || H || 0xbc
     *            Note that maskedDB is already generated from the Xor operation
     */
    DX_PAL_MemCopy(&(EMPadOutputBuffer[PrvNNewSizeBytes - Context_ptr->HASH_Result_Size * 4 - 1]),
                   (uint8_t *)Context_ptr->HASH_Result, Context_ptr->HASH_Result_Size * 4);

    EMPadOutputBuffer[PrvNNewSizeBytes - Context_ptr->HASH_Result_Size * 4 - 1 + Context_ptr->HASH_Result_Size * 4] =
        0xbc;

    /*
     *    FINISH 9.1.1
     */

    /*
     *    8.1.1 <2.a>
     *    Convert the encoded message EM to an integer message representative m
     *      NO NEED TO ! :-)
     */

    /*
     *    8.1.1 <2.b>
     *    Apply the RSASP1 signature primitive to the RSA private key K and the message
     *  representative m to produce an integer signature representative s
     *
     */

    /* ------------------------------------------- */
    /* RSA computation                              */
    /* ------------------------------------------- */

    /* ......................... execute RSA encryped ....................... */
    /* ---------------------------------------------------------------------- */

    /* execute the expomnent - after correct building it is working with either CRT or PAIR mode */
    Error = CRYS_RSA_PRIM_Decrypt(&Context_ptr->PrivUserKey, &Context_ptr->PrimeData, EMPadOutputBuffer,
                                  (uint16_t)PrvNNewSizeBytes, Output_ptr);

    if (Error != CRYS_OK) {
        return Error;
    }

    return Error;
}

#endif /* !defined(_INTERNAL_CRYS_NO_RSA_SCHEME_21_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_SIGN_SUPPORT) */

#endif /* CRYS_NO_HASH_SUPPORT */
#endif /* CRYS_NO_PKI_SUPPORT */

#if defined(CRYS_NO_HASH_SUPPORT) || defined(CRYS_NO_PKI_SUPPORT)

void CRYS_RSA_PSS21_UTIL_foo(void)
{
}
#endif // _INTERNAL_CRYS_NO_RSA_SIGN_SUPPORT
#endif /* defined(CRYS_NO_HASH_SUPPORT) || defined(CRYS_NO_PKI_SUPPORT) */
