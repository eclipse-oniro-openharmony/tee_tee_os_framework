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
#include "dx_pal_mem.h"
#ifndef DX_OEM_FW
#include "crys.h"
#else
#include "oem_crys.h"
#endif
#include "dx_pal_types.h"
#include "crys_common_math.h"
#include "crys_rsa_error.h"
#include "crys_hash.h"
#include "crys_hash_error.h"
#include "crys_rsa_local.h"
#include "crys_rnd_error.h"
#include "compiler.h"
#include "cc_acl.h"

/* *********************** Defines ************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs ************************* */

/* *********************** Global Data *********************** */

#if DEBUG_OAEP_SEED
#include "CRYS_RSA_PSS21_defines.h"
extern uint8_t SaltDB[NUM_OF_SETS_TEST_VECTORS][NUM_OF_TEST_VECTOR_IN_SET][CRYS_RSA_PSS_SALT_LENGTH];
extern uint16_t Global_Set_Index;
extern uint16_t Global_vector_Index;
#endif

/* ************ Private function prototype ************** */

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

#ifndef DX_OEM_FW
#if !defined(_INTERNAL_CRYS_NO_RSA_ENCRYPT_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_VERIFY_SUPPORT)
/* *********************** Public Functions **************************** */
/*
   @brief
   CRYS_RSA_PSS_OAEPEncode implements the the Encoding operation according to the PKCS#1 as defined
   in PKCS#1 v2.1 7.1.1 (2) and PKCS#1 v2.0

*/
CRYSError_t CRYS_RSA_PSS_OAEPEncode(CRYS_PKCS1_HashFunc_t hashFunc, CRYS_PKCS1_MGF_t MGF, uint8_t *M_ptr,
                                    uint16_t MSize, uint8_t *P_ptr, uint32_t PSize,
                                    uint16_t emLen, /* The value is set before the call */
                                    CRYS_RSAPrimeData_t *PrimeData_ptr, uint8_t *EMInput_ptr,
                                    CRYS_PKCS1_version PKCS1_ver)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;

    /* For PKCS1 Ver21 standard: emLen = k = Public mod N size */
    /* Used for output of MGF1 function ; the size is at most emLen */
    uint8_t *MaskDB_Ptr = ((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->MaskDB;
    uint8_t HashOutputSize;
    uint16_t TmpSize, I;
    uint8_t *TmpByte_ptr;
    uint8_t *EM_ptr = &EMInput_ptr[1];
    uint8_t VersionConstant; /* Used to distinguish between Ver 2.1 and others for some memory manipulations */

#if DEBUG_OAEP_SEED
    uint8_t *SeedTEST =
        SaltDB[Global_Set_Index]
              [Global_vector_Index]; /* A Data Base created in the test file for checking the Encrypted operation */
#endif                               /* otherwise the seed is generated strait to EM_ptr */

    /* FUNCTION LOGIC */

    /* .................. initializing local variables ................... */
    /* ------------------------------------------------------------------- */

    /* Initializing the first Byte to Zero */
    EMInput_ptr[0] = 0;

    switch (hashFunc) {
    case CRYS_HASH_MD5_mode:
        HashOutputSize = CRYS_HASH_MD5_DIGEST_SIZE_IN_BYTES;
        break;
    case CRYS_HASH_SHA1_mode:
        HashOutputSize = CRYS_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
        break;
    case CRYS_HASH_SHA224_mode:
        HashOutputSize = CRYS_HASH_SHA224_DIGEST_SIZE_IN_BYTES;
        break;
    case CRYS_HASH_SHA256_mode:
        HashOutputSize = CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES;
        break;
    case CRYS_HASH_SHA384_mode:
        HashOutputSize = CRYS_HASH_SHA384_DIGEST_SIZE_IN_BYTES;
        break;
    case CRYS_HASH_SHA512_mode:
        HashOutputSize = CRYS_HASH_SHA512_DIGEST_SIZE_IN_BYTES;
        break;
    default:
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    if (PKCS1_ver == CRYS_PKCS1_VER21)
        VersionConstant = 2;
    else
        VersionConstant = 1;

    /* ------------------------------------------------------------*
     * Step 1 : If the length of P is greater than                *
     *           the input limitation for the hash                *
     *           function (2^29 octets for SHA-1)                 *
     *           then output "parameter string too long" and stop *
     *                                                            *
     *           In PKCS1_Ver2.1 L = P                            *
     * ------------------------------------------------------------ */

    /* if the P / L larger then 2^29 which is the input limitation for HASH
       return error (to prevent an overflow on the transition to bits ) */
    if (PSize >= (1 << 29))
        return CRYS_RSA_BASE_OAEP_ENCODE_PARAMETER_STRING_TOO_LONG;

    /* -------------------------------------------------*
     * Step 2 : If ||M|| > emLen-2hLen-1 then output   *
     *   "message too long" and stop.                  *
     *                                                 *
     * for PKCS1_Ver2.1 Step 1 <b>:               *
     * If ||M|| > emLen - 2hLen - 2                    *
     * ------------------------------------------------- */

    if ((uint32_t)MSize + 2 * HashOutputSize + VersionConstant > emLen)
        return CRYS_RSA_BASE_OAEP_ENCODE_MESSAGE_TOO_LONG;

    /* -----------------------------------------------------*
     * Step 3 : Generate an octet string PS consisting of  *
     *           emLen-||M||-2hLen-1 zero octets.          *
     *           The length of PS may be 0.                *
     *                                                     *
     * PKCS1_VER21 Step 2 <b>                    *
     *          Generate an octet string PS consisting of *
     *           emLen-||M||-2hLen-2 zero octets.          *
     *           The length of PS may be 0                 *
     * ----------------------------------------------------- */
    DX_PAL_MemSet((uint8_t *)&EM_ptr[2 * HashOutputSize], 0x0, emLen - MSize - 2 * HashOutputSize - VersionConstant);

    /* --------------------------------------------------------------*
     * Step 4 : Let pHash = Hash(P), an octet string of length hLen.*
     * PKCS1_VER21 Step 2 <a> where L is denoted by P usually and   *
     * empty string                                                 *
     * -------------------------------------------------------------- */
    if (P_ptr != DX_NULL) {
        Error = CRYS_HASH(hashFunc, P_ptr, PSize,
                          ((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->HashResultBuff);
        if (Error != CRYS_OK) {
            return Error;
        }
    } else {
        Error =
            CRYS_HASH_Init(&(((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->HashUsercontext), hashFunc);
        if (Error != CRYS_OK) {
            return Error;
        }

        Error = CRYS_HASH_Finish(&(((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->HashUsercontext),
                                 ((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->HashResultBuff);
        if (Error != CRYS_OK) {
            return Error;
        }
    }
    /* Copy the Hash result to the proper place in the output buffer */
    DX_PAL_MemCopy(&EM_ptr[HashOutputSize],
                   (uint8_t *)(((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->HashResultBuff),
                   HashOutputSize);

    /* ---------------------------------------------------------*
     * Step 5 : Concatenate pHash, PS, the message M,          *
     *           and other padding to form a data block DB as  *
     *           DB = pHash || PS || 01 || M                   *
     *                                                         *
     * PKCS1_VER21 Step 2 <c>                                  *
     * --------------------------------------------------------- */
    /* EM_ptr[emLen-MSize-1]=0x01; */
    EM_ptr[emLen - MSize - 1 - (VersionConstant - 1)] =
        0x01; /* because emLen = PubNSize ; but EM_ptr points to place 1 */
    DX_PAL_MemCopy((uint8_t *)&EM_ptr[emLen - MSize - (VersionConstant - 1)], M_ptr,
                   MSize); /* because emLen = PubNSize; but EM_ptr points to place 1 */

    /* --------------------------------------------------------------*
     * Step 6 : Generate a random octet string seed of length hLen. *
     * PKCS1_VER21 Step 2 <d>                                       *
     * -------------------------------------------------------------- */

#if DEBUG_OAEP_SEED
    /* Only for PKCS#1 ver2.1 SHA1 - Salt length is 20 */
    DX_PAL_MemCopy(EM_ptr, SeedTEST, CRYS_RSA_PSS_SALT_LENGTH);
#else
    Error = CRYS_RND_GenerateVector(HashOutputSize, EM_ptr);
    if (Error != CRYS_OK) {
        return Error;
    }

#endif

    /* -----------------------------------------------*
     * Step 7 : Let dbMask = MGF(seed, emLen-hLen).  *
     * PKCS1_VER21 Step 2 <e> Let                    *
     *      dbMask = MGF(seed, emLen-hLen-1).        *
     * ----------------------------------------------- */
    /*
     * Add by y00201671 begin:for CTS  RSA/ECB/OAEPWithSHA-224/256/384/512AndMGF1Padding
     * In Android CTS:use SHA1 to do CRYS_RSA_OAEPMGF1
     */
    uint16_t hLenModifyForCTS                      = CRYS_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
    CRYS_HASH_OperationMode_t hashFuncModifyForCTS = CRYS_HASH_SHA1_mode;
    // Add by y00201671 end
    switch (MGF) {
    case CRYS_PKCS1_MGF1:

        Error = CRYS_RSA_OAEPMGF1(hLenModifyForCTS, /* HashOutputSize, */ /* The size is given for the function in words */
                                  &EM_ptr[0],                           /* ok */
                                  HashOutputSize,                       /* ok */
                                  emLen - HashOutputSize - (VersionConstant - 1),                            /* ok */
                                  &(((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->MaskDB[0]), /* ok */
                                  hashFuncModifyForCTS, /* hashFunc, */
                                  (uint8_t *)PrimeData_ptr->DataIn, (uint8_t *)PrimeData_ptr->DataOut);

        if (Error != CRYS_OK) {
            return Error;
        }
        break;

        /* Currently for PKCS1 Ver 2.1 only MGF1 is implemented */
    case CRYS_PKCS1_NO_MGF:
    default:

        return CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;
    }

    /* -----------------------------------------------*
     * Step 8 : Let maskedDB = DB \xor dbMask.       *
     *  PKCS1_VER21 Step 2 <f>                       *
     * ----------------------------------------------- */

    TmpSize     = emLen - HashOutputSize - (VersionConstant - 1);
    TmpByte_ptr = &EM_ptr[HashOutputSize];
    for (I = 0; TmpSize > I; I++)
        *(TmpByte_ptr + I) ^= ((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->MaskDB[I];

    MaskDB_Ptr = TmpByte_ptr;

    /* -----------------------------------------------*
     * Step 9 : Let seedMask = MGF(maskedDB, hLen).  *
     * PKCS1_VER21 Step 2 <g>                        *
     * ----------------------------------------------- */
    /*
     * Add by y00201671 begin:for CTS  RSA/ECB/OAEPWithSHA-224/256/384/512AndMGF1Padding
     * In Android CTS:use SHA1 to do CRYS_RSA_OAEPMGF1
     */
    hLenModifyForCTS     = CRYS_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
    hashFuncModifyForCTS = CRYS_HASH_SHA1_mode;
    // Add by y00201671 end

    switch (MGF) {
    case CRYS_PKCS1_MGF1:

        Error = CRYS_RSA_OAEPMGF1(
            hLenModifyForCTS, /* HashOutputSize, */ /* This is important its uint32 as a result of size limits */
            MaskDB_Ptr, (uint16_t)(emLen - HashOutputSize - (VersionConstant - 1)), HashOutputSize,
            &(((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->SeedMask[0]),
            hashFuncModifyForCTS, /* hashFunc, */
            (uint8_t *)PrimeData_ptr->DataIn, (uint8_t *)PrimeData_ptr->DataOut);

        if (Error != CRYS_OK)
            return Error;

        break;

    /* Currently for PKCS1 Ver 2.1 only MGF1 is implemented */
    case CRYS_PKCS1_NO_MGF:
    default:
        return CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;

    } /* end of MGF type switch */

    /* -----------------------------------------------*
     * Step 10: Let maskedSeed = seed \xor seedMask. *
     * PKCS1_VER21 Step 2 <h>                        *
     * ----------------------------------------------- */

    TmpSize     = HashOutputSize;
    TmpByte_ptr = &EM_ptr[0];
    for (I = 0; TmpSize > I; I++)
        *(TmpByte_ptr + I) ^= ((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->SeedMask[I];

    /* ---------------------------------------------*
     * Step 11 : Let EM = maskedSeed || maskedDB.  *
     * PKCS1_VER21 Step 2 <i>:            *
     * Let EM = 0x00 || maskedSeed || maskedDB.    *
     * This step is done !                         *
     * --------------------------------------------- */

    /* Clear Internal buffers */
    DX_PAL_MemSet((PrimeData_ptr->InternalBuff), 0, CRYS_RSA_TMP_BUFF_SIZE);
    return CRYS_OK;
}
#endif /* !defined(CRYS_NO_RSA_ENCRYPT_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_VERIFY_SUPPORT) */
#endif /* !defined DX_OEM_FW */

#if !defined(CRYS_NO_RSA_DECRYPT_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_SIGN_SUPPORT)
/* -------------------------------------------------------------
 *    Function Name: CRYS_RSA_PSS_OAEPDecode
 *    Date:   15-4-2002
 *    Author:    Ohad Shperling
 *
 *    Inputs:
 *    Outputs:
 *
 *    Algorithm: according PKCS1-v.2/1
 *    Update History:
 *    Date:        Description:
 * ----------------------------------------------------------- */

CRYSError_t CRYS_RSA_PSS_OAEPDecode(CRYS_PKCS1_HashFunc_t hashFunc, CRYS_PKCS1_MGF_t MGF, uint8_t *EM_ptr,
                                    uint16_t EMSize, uint8_t *P_ptr, uint32_t PSize,
                                    CRYS_RSAPrimeData_t *PrimeData_ptr, /* Only for stack memory save */
                                    uint8_t *M_ptr, uint16_t *MSize_ptr)
{
    /* FUNCTION DECLERATIONS */

    uint8_t HashOutputSize;
    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;

    uint8_t *maskedDB_ptr;
    uint16_t I, TmpSize;
    uint8_t *TmpByte_ptr;

    /* FUNCTION LOGIC */

    /* .................. initializing local variables ................... */
    /* ------------------------------------------------------------------- */

    switch (hashFunc) {
    case CRYS_HASH_MD5_mode: /* MD5 is not recomended in PKCS1 ver 2.1 standard,
                   henceit is not supported */
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    case CRYS_HASH_SHA1_mode:
        HashOutputSize = CRYS_HASH_SHA1_DIGEST_SIZE_IN_WORDS * 4;
        break;
    case CRYS_HASH_SHA224_mode:
        HashOutputSize = CRYS_HASH_SHA224_DIGEST_SIZE_IN_WORDS * 4;
        break;
    case CRYS_HASH_SHA256_mode:
        HashOutputSize = CRYS_HASH_SHA256_DIGEST_SIZE_IN_WORDS * 4;
        break;
    case CRYS_HASH_SHA384_mode:
        HashOutputSize = CRYS_HASH_SHA384_DIGEST_SIZE_IN_WORDS * 4;
        break;
    case CRYS_HASH_SHA512_mode:
        HashOutputSize = CRYS_HASH_SHA512_DIGEST_SIZE_IN_WORDS * 4;
        break;
    default:
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }
    /* For PKCS1 Ver 2.1 P=L */
    /* --------------------------------------------------------*
     * Step 1: if the length of P is greater than the input   *
     *         limitation of the hash function (2^29 octets *
     *         for SHA-1) then output "decoding error"        *
     *          and stop.                                     *
     * -------------------------------------------------------- */
    if (PSize >= (1 << 29))
        return CRYS_RSA_BASE_OAEP_DECODE_PARAMETER_STRING_TOO_LONG;

    /* -------------------------------------------------------*
     * Step 2: If ||EM|| < 2hLen+1, then output              *
     *        "decoding error" and stop.                     *
     * ------------------------------------------------------- */
    if (EMSize < 2 * HashOutputSize + 1)
        return CRYS_RSA_BASE_OAEP_DECODE_MESSAGE_TOO_LONG;
    /* -------------------------------------------------------*
     * Step 3: Let maskedSeed be the first hLen octets of EM *
     *         and let maskedDB be the remaining             *
     *         ||EM|| - hLen octets.                         *
     * PKCS1 Ver2.1: Step <3> <b>                            *
     * ------------------------------------------------------- */
    maskedDB_ptr = EM_ptr + HashOutputSize;

    /* -------------------------------------------------------*
     * Step 4: Let seedMask = MGF(maskedDB, hLen).           *
     * PKCS1 Ver2.1: Step <3> <c>                            *
     * ------------------------------------------------------- */
    /*
     * Add by y00201671 begin:for CTS  RSA/ECB/OAEPWithSHA-224/256/384/512AndMGF1Padding
     * In Android CTS:use SHA1 to do CRYS_RSA_OAEPMGF1
     */
    uint16_t hLenModifyForCTS                      = CRYS_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
    CRYS_HASH_OperationMode_t hashFuncModifyForCTS = CRYS_HASH_SHA1_mode;
    // Add by y00201671 end

    switch (MGF) {
    case CRYS_PKCS1_MGF1:

        Error = CRYS_RSA_OAEPMGF1(hLenModifyForCTS, /* HashOutputSize, */
                                  maskedDB_ptr, (uint16_t)(EMSize - HashOutputSize), HashOutputSize,
                                  &(((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->SeedMask[0]),
                                  hashFuncModifyForCTS, /* hashFunc, */
                                  (uint8_t *)PrimeData_ptr->DataIn, (uint8_t *)PrimeData_ptr->DataOut);
        if (Error != CRYS_OK) {
            return Error;
        }
        break;

    /* Currently for PKCS1 Ver 2.1 only MGF1 is implemented */
    case CRYS_PKCS1_NO_MGF:
    default:
        return CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;
    }

    /* -------------------------------------------------------*
     * Step 5: Let seed = maskedSeed \xor seedMask.          *
     * PKCS1 Ver2.1: Step <3> <d>                            *
     * ------------------------------------------------------- */
    TmpSize     = HashOutputSize;
    TmpByte_ptr = &EM_ptr[0];
    for (I = 0; TmpSize > I; I++)
        *(TmpByte_ptr + I) ^= ((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->SeedMask[I];

    /* -------------------------------------------------------*
     * Step 6: Let dbMask = MGF(seed, ||EM|| - hLen).        *
     * PKCS1 Ver2.1: Step <3> <e>                            *
     * ------------------------------------------------------- */
    /*
     * Add by y00201671 begin:for CTS  RSA/ECB/OAEPWithSHA-224/256/384/512AndMGF1Padding
     * In Android CTS:use SHA1 to do CRYS_RSA_OAEPMGF1
     */
    hLenModifyForCTS     = CRYS_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
    hashFuncModifyForCTS = CRYS_HASH_SHA1_mode;
    // Add by y00201671 end
    Error = CRYS_RSA_OAEPMGF1(hLenModifyForCTS, /* HashOutputSize, */
                              EM_ptr, HashOutputSize, EMSize - HashOutputSize,
                              &(((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->MaskDB[0]),
                              hashFuncModifyForCTS, /* hashFunc, */
                              (uint8_t *)PrimeData_ptr->DataIn, (uint8_t *)PrimeData_ptr->DataOut);

    if (Error != CRYS_OK)
        return Error;

    /* -------------------------------------------------------*
     * Step 7: Let DB = maskedDB \xor dbMask.                *
     *         PKCS1 Ver2.1: Step <3> <f>                    *
     * ------------------------------------------------------- */
    TmpSize     = EMSize - HashOutputSize;
    TmpByte_ptr = &EM_ptr[0] + HashOutputSize;
    for (I = 0; TmpSize > I; I++)
        *(TmpByte_ptr + I) ^= ((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->MaskDB[I];

    /* -------------------------------------------------------*
     * Step 8: Let pHash = Hash(P), an octet string of       *
     *         length hLen.                                  *
     *                                                       *
     * PKCS1 Ver2.1: Step <3> <a>                            *
     * ------------------------------------------------------- */
    if (P_ptr != DX_NULL) {
        Error = CRYS_HASH(hashFunc, P_ptr, PSize,
                          ((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->HashResultBuff);

        if (Error != CRYS_OK) {
            return Error;
        }
    } else {
        Error =
            CRYS_HASH_Init(&(((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->HashUsercontext), hashFunc);
        if (Error != CRYS_OK) {
            return Error;
        }

        Error = CRYS_HASH_Finish(&(((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->HashUsercontext),
                                 ((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->HashResultBuff);
        if (Error != CRYS_OK) {
            return Error;
        }
    }

    /* ---------------------------------------------------------*
     * Step 9: Separate DB into an octet string pHash'         *
     *         consisting of the first hLen octets of DB,      *
     *         a (possibly empty) octet string PS consisting   *
     *         of consecutive zero octets following pHash',    *
     *         and a message M as DB = pHash' || PS || 01 || M *
     *         If there is no 01 octet to separate PS from M,  *
     *         output "decoding error" and stop.               *
     *                                                         *
     * PKCS1 Ver2.1: Step <3> <g>                              *
     * --------------------------------------------------------- */

    TmpSize     = EMSize - 2 * HashOutputSize;
    TmpByte_ptr = &EM_ptr[0] + 2 * HashOutputSize;
    for (I = 0; TmpSize > I; I++) {
        if (*(TmpByte_ptr + I) != 0x00)
            break;
    }

    if (*(TmpByte_ptr + I) != 0x01)
        return CRYS_RSA_OAEP_DECODE_ERROR;

    TmpByte_ptr += I;

    /* ------------------------------------------------------*
     * Step 10: If pHash' does not equal pHash, output      *
     *          "decoding error" and stop.                  *
     *                                                      *
     * PKCS1 Ver2.1: Step <3> <g>                           *
     * ------------------------------------------------------ */
    if (DX_PAL_MemCmp(&EM_ptr[0] + HashOutputSize,
                      (uint8_t *)(((CRYS_OAEP_Data_t *)((void *)PrimeData_ptr->InternalBuff))->HashResultBuff),
                      HashOutputSize))
        return CRYS_RSA_OAEP_DECODE_ERROR;

    /* -----------------------------------------------*
     * Step 11: Output M.                            *
     * ----------------------------------------------- */
    /* Checking that the Output buffer Size is enough large for result output */
    if (*MSize_ptr < EMSize - 2 * HashOutputSize - I - 1) {
        *MSize_ptr = EMSize - 2 * HashOutputSize - I - 1;
        return CRYS_RSA_DECRYPT_INVALID_OUTPUT_SIZE;
    }

    else if (*MSize_ptr > EMSize - 2 * HashOutputSize - I - 1)
        /* set the actual output message size */
        *MSize_ptr = EMSize - 2 * HashOutputSize - I - 1;

    /* at this point TmpByte_ptr points to 01 */
    TmpByte_ptr += 1;

    /* at this point TmpByte_ptr points to M  */
    DX_PAL_MemCopy(M_ptr, TmpByte_ptr, *MSize_ptr);

    /* Clear Internal buffers */
    DX_PAL_MemSet((PrimeData_ptr->InternalBuff), 0, CRYS_RSA_TMP_BUFF_SIZE);

    return CRYS_OK;
}
#endif /* !defined(CRYS_NO_RSA_DECRYPT_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_SIGN_SUPPORT) */

/* ******************************************************************************************************* */

/* -------------------------------------------------------------
 *    Function Name: CRYS_RSA_OAEPMGF1
 *    Date:   09-1-2005
 *    Author:    Ohad Shperling
 *
 *    Inputs:
 *    Outputs:
 *
 *    Algorithm: according to PKCS1-v.2_1
 *
 *    Update History:
 *    Date:        Description:
 * ----------------------------------------------------------- */

CRYSError_t CRYS_RSA_OAEPMGF1(uint16_t hLen,                  /* size in Bytes */
                              uint8_t *Z_ptr, uint16_t ZSize, /* size in Bytes */
                              uint32_t L, uint8_t *Mask_ptr, CRYS_PKCS1_HashFunc_t hashFunc,
                              uint8_t *T_Buf,     /* T_Buf is a buffer used for data manipulation for the function to use
                                                     instead of allocating the space on stack */
                              uint8_t *T_TMP_Buf) /* T_TMP_Buf is a buffer used for data manipulation for the function to
                                                     use instead of allocating the space on stack */
{
    /* FUNCTION DECLARATIONS */

    uint32_t Counter = 0;
    uint32_t CounterMaxSize, Tmp32Bit;
    CRYSError_t Error;

    CRYS_HASH_Result_t HashResultBuff;
    uint8_t HashOutSize_Bytes;
    uint8_t *Output_ptr;

    uint8_t *T = T_Buf; /* The size of T for MGF1 used to be 2048/8 now the size of T_Buf in the context is even bigger */
    uint8_t *T_TMP = T_TMP_Buf;

    Output_ptr = T;
    DX_PAL_MemCopy(T_TMP, Z_ptr, ZSize);

    /* ---------------------------------------------------------------------*
     * Step 1:    If l > 2^32 hLen, output "mask too long" and stop.          *
     * --------------------------------------------------------------------- */

    if ((uint32_t)(CRYS_RSA_MGF_2_POWER_32 * hLen) < L)
        return CRYS_RSA_BASE_MGF_MASK_TOO_LONG;

    /* limit the size to the temp buffer size that is the maximum key length */
    if (CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * sizeof(uint32_t) < L)
        return CRYS_RSA_BASE_MGF_MASK_TOO_LONG;

    /* ---------------------------------------------------------------------*
     * Step 2:  Let T  be the empty octet string.                          *
     * --------------------------------------------------------------------- */

    /* ---------------------------------------------------------------------*
     * Step 3:  For counter from 0 to  | l / hLen | -1 , do the following: *
     *          a.    Convert counter to an octet string C of length 4       *
     *              with the primitive I2OSP:                              *
     *               C = I2OSP (counter, 4)                                *
     *          b.    Concatenate the hash of the seed Z and C to the octet  *
     *               string T:   T = T || Hash (Z || C)                    *
     * --------------------------------------------------------------------- */

    CounterMaxSize = (uint32_t)(L / hLen); /* the casting makes |_ l/Lenm _| +1 -1 = only the casting */

    switch (hashFunc) {
    case CRYS_HASH_MD5_mode:
        HashOutSize_Bytes = CRYS_HASH_MD5_DIGEST_SIZE_IN_BYTES;
        break;
    case CRYS_HASH_SHA1_mode:
        HashOutSize_Bytes = CRYS_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
        break;
    case CRYS_HASH_SHA224_mode:
        HashOutSize_Bytes = CRYS_HASH_SHA224_DIGEST_SIZE_IN_BYTES;
        break;
    case CRYS_HASH_SHA256_mode:
        HashOutSize_Bytes = CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES;
        break;
    case CRYS_HASH_SHA384_mode:
        HashOutSize_Bytes = CRYS_HASH_SHA384_DIGEST_SIZE_IN_BYTES;
        break;
    case CRYS_HASH_SHA512_mode:
        HashOutSize_Bytes = CRYS_HASH_SHA512_DIGEST_SIZE_IN_BYTES;
        break;
    default:
        return CRYS_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    for (Counter = 0; Counter <= CounterMaxSize; Counter++) {
        /* --------------------------------------------------------------------
         *          a.    Convert counter to an octet string C of length 4
         *              with the primitive I2OSP:   C = I2OSP (counter, 4)
         * -------------------------------------------------------------------- */

        /* T_TMP = H||C */

#ifndef BIG__ENDIAN
        Tmp32Bit = CRYS_COMMON_REVERSE32(Counter);
#else
        Tmp32Bit = Counter;
#endif

        DX_PAL_MemCopy(&T_TMP[0] + ZSize, &Tmp32Bit, sizeof(uint32_t));

        /* --------------------------------------------------------------------
         *          b.    Concatenate the hash of the seed Z and C to the octet
         *               string T: T = T || Hash (Z || C)
         * -------------------------------------------------------------------- */

        /* Hash Z||C */
        Error = CRYS_HASH(hashFunc, T_TMP, ZSize + 4, HashResultBuff);

        if (Error != CRYS_OK)
            return Error;

        DX_PAL_MemCopy(Output_ptr, (uint8_t *)HashResultBuff, HashOutSize_Bytes);
        Output_ptr += hLen;
    }

    /* ---------------------------------------------------------------------*
     * Step 4:  Output the leading l octets of T as the octet string mask. *
     * --------------------------------------------------------------------- */
    DX_PAL_MemCopy(Mask_ptr, (uint8_t *)T, L);

    return CRYS_OK;
}
#endif /* CRYS_NO_HASH_SUPPORT */
#endif /* CRYS_NO_PKI_SUPPORT */

#ifndef DX_OEM_FW
#if !defined(_INTERNAL_CRYS_NO_RSA_ENCRYPT_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_VERIFY_SUPPORT)

/* ******************************************************************************************************* */

/*
   @brief
   RSA_SCHEMES_Encrypt implements the RSAES-OAEP algorithm as defined
   in PKCS#1 v2.1 8.1 and in PKCS#1 v1.5 8.1

    This function combines the RSA encryption primitive and the
    EME-OAEP encoding method, to provide an RSA-based encryption
    method that is semantically secure against adaptive
    chosen-ciphertext attacks. For more details, please refere to
    the PKCS#1 standard.

    The actual macro that will be used by the user is:
    CRYS_RSA_OAEP_Encrypt       - for v2.1
    CRYS_RSA_PKCS1v15_Encrypt - for v1.5

   @param[in] UserPubKey_ptr - A pointer to the public key data structure of the User.
   @param[in] PrimeData_ptr - A pointer to a CRYS_RSAPrimeData_t
                   that is used for the Encryption operation
   @param[in] hashFunc - The hash function to be used.
                         The hash functions supported: SHA1, SHA-256/284/512,
                         MD5 (MD5 - allowed only for PKCS#1 v1.5).
   @param[in] L - The label input pointer. Relevant for PKCS#1 Ver2.1 only, may be NULL also.
                  For PKCS#1 Ver1.5 it is an empty string (NULL).
   @param[in] Llen - The label length. Relevant for PKCS#1 Ver2.1 only (see notes above).
   @param[in] MGF - the mask generation function. PKCS#1 v2.1
                    defines MGF1, so the currently allowed value is CRYS_PKCS1_MGF1.
   @param[in] Data_ptr - Pointer to the data to encrypt.
   @param[in] DataSize - The size, in bytes, of the data to encrypt.
             \Note: The data size must be:
                1. for PKCS #1 v.2.1  DataSize <= PrivKey_ptr->N.len - 2*HashLen - 2.
                2. for PKCS #1 v.1.5  DataSize <= PrivKey_ptr->N.len - 11.
   @param[out] Output_ptr - Pointer to the encrypted data. The size of the data is always
                equal to the RSA key (modulus) size, in bytes. Therefore the size
                    of allocated buffer must be at least of this size.

   @return CRYSError_t - CRYS_OK, CRYS_BAD_PARAM, CRYS_OUT_OF_RANGE
*/
CEXPORT_C CRYSError_t _DX_RSA_SCHEMES_Encrypt(CRYS_RSAUserPubKey_t *UserPubKey_ptr, CRYS_RSAPrimeData_t *PrimeData_ptr,
                                              CRYS_RSA_HASH_OpMode_t hashFunc, uint8_t *L, uint16_t Llen,
                                              CRYS_PKCS1_MGF_t MGF, uint8_t *DataIn_ptr, uint16_t DataInSize,
                                              uint8_t *Output_ptr, CRYS_PKCS1_version PKCS1_ver)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;

    /* The modulus size in Bytes */
    uint16_t K;
    uint8_t HashOutputSize;

    /* In order to save stack memory place -
     * It is required that the Output_ptr is at least the size of the modulus
     * It is also required that the RSA computation is done in-place */
    uint8_t *EB_buff = Output_ptr;

    CRYSRSAPubKey_t *PubKey_ptr;
    CRYS_HASH_OperationMode_t CrysHashOpMode;
    uint32_t PSSize;

    /* FUNCTION LOGIC */

    /* ............... if not supported exit .............................. */
    /* -------------------------------------------------------------------- */
    RETURN_IF_RSA_UNSUPPORTED(UserPubKey_ptr, PrimeData_ptr, hashFunc, L, Llen, MGF, DataIn_ptr, DataInSize Output_ptr,
                              PKCS1_ver, K, HashOutputSize, EB_buff, PubKey_ptr, CrysHashOpMode, PSSize, Error, Error,
                              Error, Error, Error, Error, Error);

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context pointer is DX_NULL return an error */
    if (UserPubKey_ptr == DX_NULL)
        return CRYS_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR;

    /* checking the Prime Data pointer */
    if (PrimeData_ptr == DX_NULL)
        return CRYS_RSA_PRIM_DATA_STRUCT_POINTER_INVALID;

    /* check if the hash operation mode is legal */
    if (hashFunc >= CRYS_RSA_HASH_NumOfModes)
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

    /* check if the MGF operation mode is legal */
    if (CRYS_RSA_NumOfMGFFunctions <= MGF)
        return CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;

    /* check that the PKCS1 version argument is legal */
    if (PKCS1_ver >= CRYS_RSA_NumOf_PKCS1_versions)
        return CRYS_RSA_PKCS1_VER_ARG_ERROR;

    /* if the users Data In pointer is illegal return an error */
    /* note - it is allowed to encrypt a message of size zero ; only on this case a NULL is allowed */
    if (DataIn_ptr == DX_NULL && DataInSize != 0)
        return CRYS_RSA_DATA_POINTER_INVALID_ERROR;

    /* If the output pointer is DX_NULL return Error */
    if (Output_ptr == DX_NULL)
        return CRYS_RSA_INVALID_OUTPUT_POINTER_ERROR;

    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ, UserPubKey_ptr, sizeof(CRYS_RSAUserPubKey_t)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, PrimeData_ptr, sizeof(CRYS_RSAPrimeData_t)) ||
        ((L != DX_NULL) && DxCcAcl_IsBuffAccessOk(ACCESS_READ, L, Llen)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ, DataIn_ptr, DataInSize) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, Output_ptr, DataInSize)) {
        return CRYS_RSA_ILLEGAL_PARAMS_ACCORDING_TO_PRIV_ERROR;
    }

    PubKey_ptr = (CRYSRSAPubKey_t *)UserPubKey_ptr->PublicKeyDbBuff;

    if (UserPubKey_ptr->valid_tag != CRYS_RSA_PUB_KEY_VALIDATION_TAG)
        return CRYS_RSA_PUB_KEY_VALIDATION_TAG_ERROR;

    if (Llen == 0)
        L = DX_NULL;

    /* .................. initializing local variables ................... */
    /* ------------------------------------------------------------------- */

    /* Initialize K with the modulus size in Bytes */
    K = ((uint16_t)PubKey_ptr->nSizeInBits + 7) / 8;

#ifdef DEBUG
    /* Initialize the Output_ptr to Zero */
    DX_PAL_MemSet(EB_buff, 0, K);
#endif

    /* -------------------------------------------------------*
     * Perform Encoding and Encryption accordimg to PKCS1      *
     * Versions: VER21 or VER15                              *
     * ------------------------------------------------------- */

    switch (PKCS1_ver) {
#ifndef _INTERNAL_CRYS_NO_RSA_SCHEME_15_SUPPORT
    case CRYS_PKCS1_VER15:
        /* -------------------------------------------------------*
         * Step 1 : Check modulus and data sizes              *
         * ------------------------------------------------------- */
        /* Check the modulus size is legal */
        if (K < 3 + PS_MIN_LEN)
            return CRYS_RSA_INVALID_MODULUS_SIZE;

        if (DataInSize + 3 + PS_MIN_LEN > K)
            return CRYS_RSA_INVALID_MESSAGE_DATA_SIZE;
        /* size of PS buffer, it is >= PS_MIN_LEN  */
        PSSize = K - 3 - DataInSize;

        /* -------------------------------------------------------*
         * Step 2 :  Encode the message                          *
         * ------------------------------------------------------- */

        EB_buff[0] = 0x00; /* set the 00 */
        EB_buff[1] = 0x02; /* Block type for EME-PKCS1-v1_5 */

        /* Generate random non-zero bytes for PS */
        Error = RsaGenRndNonZeroVect(&EB_buff[2], PSSize);
        if (Error)
            return Error;
        /* 0-byte after PS */
        EB_buff[K - DataInSize - 1] = 0x00;
        /* Copy the message data */
        DX_PAL_MemCopy(&EB_buff[K - DataInSize], DataIn_ptr, DataInSize);

        break;
#endif

#ifndef _INTERNAL_CRYS_NO_RSA_SCHEME_21_SUPPORT
    case CRYS_PKCS1_VER21:

        switch (hashFunc) {
        case CRYS_RSA_HASH_MD5_mode: /* MD5 is not reccomended in PKCS1 ver 2.1 standard,
                                       hence it is not supported */
            return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        case CRYS_RSA_HASH_SHA1_mode:
            HashOutputSize = CRYS_HASH_SHA1_DIGEST_SIZE_IN_WORDS * 4;
            CrysHashOpMode = CRYS_HASH_SHA1_mode; /* changing the hash mode to CRYS definition */
            break;
        case CRYS_RSA_HASH_SHA224_mode:
            HashOutputSize = CRYS_HASH_SHA224_DIGEST_SIZE_IN_WORDS * 4;
            CrysHashOpMode = CRYS_HASH_SHA224_mode; /* changing the hash mode to CRYS definition */
            break;
        case CRYS_RSA_HASH_SHA256_mode:
            HashOutputSize = CRYS_HASH_SHA256_DIGEST_SIZE_IN_WORDS * 4;
            CrysHashOpMode = CRYS_HASH_SHA256_mode; /* changing the hash mode to CRYS definition */
            break;
        case CRYS_RSA_HASH_SHA384_mode:
            HashOutputSize = CRYS_HASH_SHA384_DIGEST_SIZE_IN_WORDS * 4;
            CrysHashOpMode = CRYS_HASH_SHA384_mode; /* changing the hash mode to CRYS definition */
            break;
        case CRYS_RSA_HASH_SHA512_mode:
            HashOutputSize = CRYS_HASH_SHA512_DIGEST_SIZE_IN_WORDS * 4;
            CrysHashOpMode = CRYS_HASH_SHA512_mode; /* changing the hash mode to CRYS definition */
            break;
        default:
            return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        }

        /* if mLen>k-2*hLen-2 output message too long */
        if ((uint32_t)DataInSize + 2 * HashOutputSize + 2 > K)
            return CRYS_RSA_INVALID_MESSAGE_DATA_SIZE;

        /* -------------------------------------------------------*
         * Step 2 : Apply the EME-OAEP encoding operation to     *
         *   the message M and the label L to produce a          *
         *   ciphertext of length k octets.                      *
         * ------------------------------------------------------- */

        Error = CRYS_RSA_PSS_OAEPEncode(CrysHashOpMode, MGF, DataIn_ptr, DataInSize, L, Llen,
                                        /* The value is set before the call */
                                        K, PrimeData_ptr, EB_buff, PKCS1_ver); /* room for the first zero octet */
        if (Error != CRYS_OK)
            return Error;
        break;
#endif
    default:
        return CRYS_RSA_PKCS1_VER_ARG_ERROR;
    }

    /* ------------------------------------------- */
    /* Step 3 : RSA computation                  */
    /* ------------------------------------------- */

    Error = CRYS_RSA_PRIM_Encrypt(UserPubKey_ptr, PrimeData_ptr, EB_buff, K, Output_ptr);

    return Error;

#endif /* CRYS_NO_HASH_SUPPORT */
#endif /* CRYS_NO_PKI_SUPPORT */

} /* END OF _DX_RSA_SCHEMES_Encrypt */
#endif /* !defined(_INTERNAL_CRYS_NO_RSA_ENCRYPT_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_VERIFY_SUPPORT) */
#endif /* !defined (DX_OEM_FW) */

#if !defined(_INTERNAL_CRYS_NO_RSA_DECRYPT_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_SIGN_SUPPORT)
/* ******************************************************************************************************* */
/*
   @brief
   RSA_SCHEMES_Decrypt implements the RSAES-OAEP algorithm as defined
   in PKCS#1 v2.1 8.1 and in PKCS#1 v1.5

       This function combines the RSA decryption primitive and the
       EME-OAEP decoding method, to provide an RSA-based decryption
       method that is semantically secure against adaptive
       chosen-ciphertext attacks. For more details, please refer to
       the PKCS#1 standard.

   @param[in] UserPrivKey_ptr - Pointer to the private key data structure.
                   \Note: The representation (pair or quintuple)
                    and hence the algorithm (CRT or not) is determined
                    by the Private Key data structure. Using CRYS_Build_PrivKey
                    or CRYS_Build_PrivKeyCRT determines which algorithm will be used.

   @param[in] PrimeData_ptr - Pointer to a CRYS_RSAPrimeData_t which is used for the
                                 Encryption operation

   @param[in] hashFunc - The hash function to be used.
                         The hash functions supported: SHA1, SHA-256/284/512,
                         MD5 (MD5 - allowed only for PKCS#1 v1.5).

   @param[in] L - The label input pointer. Relevant for PKCS#1 Ver2.1 only, may be NULL also.
                  For PKCS#1 Ver1.5 it is an empty string (NULL).
   @param[in] Llen - The label length. Relevant for PKCS#1 Ver2.1 only (see notes above).
   @param[in] MGF - The mask generation function. PKCS#1 v2.1 defines MGF1,
                    so the only value allowed here is CRYS_PKCS1_MGF1.
   @param[in] Data_ptr - Pointer to the data to decrypt.
   @param[in] DataSize - The size, in bytes, of the data to decrypt.
                        \Note: The size must be = the size of the modulus.

   @param[out] Output_ptr - Pointer to the decrypted data, the size of the buffer in bytes
        must be not less than the actual size of Encrypted message, if it is known,
        else the output buffer size must be :
        1. for PKCS #1 v.2.1  *OutputSize_ptr >= PrivKey_ptr->N.len - 2*HashLen - 2.
        2. for PKCS #1 v.1.5  *OutputSize_ptr >= PrivKey_ptr->N.len - 11.
   @param[in/out] OutputSize_ptr - The size of the user passed Output_ptr buffer in bytes [in] and
        actual size of decrypted message [out].
        The minimal input size value of *OutputSize_ptr is described above.
        This value is updated with the actual number of bytes that
        are loaded to Output_ptr buffer byDecrypt function.

   @return CRYSError_t - CRYS_OK or appropriate Error message defined in the RSA module.
*/
CEXPORT_C CRYSError_t _DX_RSA_SCHEMES_Decrypt(CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                                              CRYS_RSAPrimeData_t *PrimeData_ptr, CRYS_RSA_HASH_OpMode_t hashFunc,
                                              uint8_t *L, uint16_t Llen, CRYS_PKCS1_MGF_t MGF, uint8_t *DataIn_ptr,
                                              uint16_t DataInSize, uint8_t *Output_ptr, uint16_t *OutputSize_ptr,
                                              CRYS_PKCS1_version PKCS1_ver)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;
    uint16_t K; /* The modulus size in Bytes */
    uint8_t EB_buff[CRYS_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS * 4];
    uint16_t HashOutputSizeBytes;
    CRYSRSAPrivKey_t *PrivKey_ptr;
    /* The Hash enum sent to the lower level functions */
    /* The initialization is to eliminate a warning of uninitialized variable */
    CRYS_HASH_OperationMode_t CrysHashOpMode = CRYS_HASH_NumOfModes;

    uint32_t PSSize, i;

    /* FUNCTION LOGIC */

    /* ............... if not supported exit .............................. */
    /* -------------------------------------------------------------------- */
    RETURN_IF_RSA_UNSUPPORTED(UserPrivKey_ptr, PrimeData_ptr, hashFunc, L, Llen, MGF, DataIn_ptr, DataInSize,
                              Output_ptr, OutputSize_ptr, PKCS1_ver, K, EB_buff[0], HashOutputSizeBytes, PrivKey_ptr,
                              CrysHashOpMode, PSSize, i, Error, Error, Error, Error);

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* .................. initializing local variables ................... */
    /* ------------------------------------------------------------------- */

    /* initialize the HASH mode as SHA1 - default */
    CrysHashOpMode = CRYS_HASH_SHA1_mode;

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context pointer is DX_NULL return an error */
    if (UserPrivKey_ptr == DX_NULL)
        return CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    if (PrimeData_ptr == DX_NULL)
        return CRYS_RSA_PRIM_DATA_STRUCT_POINTER_INVALID;

    /* check if the hash operation mode is legal */
    if (hashFunc >= CRYS_RSA_HASH_NumOfModes)
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

    /* check if the MGF operation mode is legal */
    if (CRYS_RSA_NumOfMGFFunctions <= MGF)
        return CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;

    /* check that the PKCS1 version argument is legal */
    if (PKCS1_ver >= CRYS_RSA_NumOf_PKCS1_versions)
        return CRYS_RSA_PKCS1_VER_ARG_ERROR;

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == DX_NULL)
        return CRYS_RSA_DATA_POINTER_INVALID_ERROR;

    /* if the data size is zero or larger then 2^29 (to prevent an overflow on the transition to bits )
       return error */
    if (DataInSize == 0)
        return CRYS_RSA_INVALID_MESSAGE_DATA_SIZE;

    /* If the output pointer is DX_NULL return Error */
    if (Output_ptr == DX_NULL)
        return CRYS_RSA_INVALID_OUTPUT_POINTER_ERROR;

    /* If the output size pointer is DX_NULL return error */
    if (OutputSize_ptr == DX_NULL)
        return CRYS_RSA_DECRYPT_OUTPUT_SIZE_POINTER_ERROR;

    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ, UserPrivKey_ptr, sizeof(CRYS_RSAUserPrivKey_t)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, PrimeData_ptr, sizeof(CRYS_RSAPrimeData_t)) ||
        ((L != DX_NULL) && DxCcAcl_IsBuffAccessOk(ACCESS_READ, L, Llen)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ, DataIn_ptr, DataInSize) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, Output_ptr, *OutputSize_ptr) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, OutputSize_ptr, sizeof(uint32_t))) {
        return CRYS_RSA_ILLEGAL_PARAMS_ACCORDING_TO_PRIV_ERROR;
    }

    PrivKey_ptr = (CRYSRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;
    if (UserPrivKey_ptr->valid_tag != CRYS_RSA_PRIV_KEY_VALIDATION_TAG)
        return CRYS_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

    if (Llen == 0)
        L = DX_NULL;

    /* .................. initializing local variables ................... */
    /* ------------------------------------------------------------------- */

    /* Initialize K with the modulus size in Bytes */
    K = (uint16_t)((PrivKey_ptr->nSizeInBits + 7) / 8);

    /* Length Checking - both for Ver 1.5 and 2.1 */
    /*
     * Donot to check that the DataInSize is equal to modulus Size
     * Because CRYS_RSA_PRIM_Decrypt support DataInSize <= modulus Size
     * Also get the info in DX datasheet:
     * Sansa Silicon for TZ v6.3-Secure CRYS Programmers Guide v1.5.pdf
     * Page 48
     *  _DX_RSA_SCHEMES_Decrypt
     * The size (in bytes) of the data to decrypt.
     * DataSize must be ¡Ü the modulus size.
     *
     * Find This bug when test Android M keystore:
     * run cts -c android.keystore.cts.SignatureTest -m
     * testSignatureGeneratedByAndroidKeyStoreVerifiesByHighestPriorityProvider But if donot do this check, Will return
     * CRYS_RSA_ERROR_IN_DECRYPTED_BLOCK_PARSING So donot make a change, need to consult Sansa
     * */
#if 1
    if (DataInSize != K)
        return CRYS_RSA_INVALID_MESSAGE_DATA_SIZE;
#endif

    /* ------------------------------------------------- */
    switch (PKCS1_ver) {
#ifndef _INTERNAL_CRYS_NO_RSA_SCHEME_15_SUPPORT
    case CRYS_PKCS1_VER15:
        /* Check the modulus size is legal */
        if (K < 11)
            return CRYS_RSA_INVALID_MODULUS_SIZE;
        break;
#endif

#ifndef _INTERNAL_CRYS_NO_RSA_SCHEME_21_SUPPORT
    case CRYS_PKCS1_VER21:

        switch (hashFunc) {
        case CRYS_RSA_HASH_MD5_mode:
            /* MD5 is not recommended in PKCS1 ver 2.1 standard, hence it is not supported */
            return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        case CRYS_RSA_HASH_SHA1_mode:
            CrysHashOpMode      = CRYS_HASH_SHA1_mode; /* changing the hash mode to CRYS definition */
            HashOutputSizeBytes = CRYS_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
            break;
        case CRYS_RSA_HASH_SHA224_mode:
            CrysHashOpMode      = CRYS_HASH_SHA224_mode;
            HashOutputSizeBytes = CRYS_HASH_SHA224_DIGEST_SIZE_IN_BYTES;
            break;
        case CRYS_RSA_HASH_SHA256_mode:
            CrysHashOpMode      = CRYS_HASH_SHA256_mode;
            HashOutputSizeBytes = CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES;
            break;
        case CRYS_RSA_HASH_SHA384_mode:
            CrysHashOpMode      = CRYS_HASH_SHA384_mode;
            HashOutputSizeBytes = CRYS_HASH_SHA384_DIGEST_SIZE_IN_BYTES;
            break;
        case CRYS_RSA_HASH_SHA512_mode:
            CrysHashOpMode      = CRYS_HASH_SHA512_mode;
            HashOutputSizeBytes = CRYS_HASH_SHA512_DIGEST_SIZE_IN_BYTES;
            break;
        default:
            return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        }

        /* Checking that the modulus have enough large */
        if (2 * HashOutputSizeBytes + 2 > K)
            return CRYS_RSA_INVALID_MODULUS_SIZE;
        break;
#endif
    default:
        return CRYS_RSA_PKCS1_VER_ARG_ERROR;

    } /* end of switch(PKCS1_ver) */

    /* ------------------------------------------- */
    /* Step 2 <b> : RSA computation              */
    /* ------------------------------------------- */
    Error = CRYS_RSA_PRIM_Decrypt(UserPrivKey_ptr, PrimeData_ptr, DataIn_ptr, DataInSize, EB_buff);
    if (Error != CRYS_OK) {
        return Error;
    }

    /* ----------------------------------------------*
     * Step 3 :  EME-OAEP Decoding            *
     * ---------------------------------------------- */

    /* for all modes */
    if (EB_buff[0] != 0x00) {
        return CRYS_RSA_ERROR_IN_DECRYPTED_BLOCK_PARSING;
    }

    /* ------------------------------------------------*
     * Perform decoding operation according to the    *
     * encoded message EM choosen PKCS1 version       *
     * ------------------------------------------------ */

    switch (PKCS1_ver) {
#ifndef _INTERNAL_CRYS_NO_RSA_SCHEME_15_SUPPORT
    case CRYS_PKCS1_VER15:

        /* ------------------------------------------------*
         * Check parameters of decrypted buffer,          *
         *    EM= 0x00||0x02||PS||0x00||M                 *
         * If EM[0] != 0 or EM[1] != 2 or no 0-byte       *
         * after PS or PS length < 8, then output "error" *
         * and stop. Output the message M.              *
         * ------------------------------------------------ */

        if (EB_buff[1] != 0x02 /* Block type for EME-PKCS1-v1_5 */) {
            return CRYS_RSA_ERROR_IN_DECRYPTED_BLOCK_PARSING;
        }

        /* find next 0-byte after PS */
        for (i = 2; i < K; i++) {
            if (EB_buff[i] == 0x00)
                break;
        }
        /* if byte 0 not present */
        if (i == K)
            return CRYS_RSA_ERROR_IN_DECRYPTED_BLOCK_PARSING;

        /* check PS size >= 8 */
        PSSize = i - 2;
        if (PSSize < PS_MIN_LEN)
            return CRYS_RSA_ERROR_IN_DECRYPTED_BLOCK_PARSING;

        if (PSSize + 3 > K)
            return CRYS_RSA_ERROR_IN_DECRYPTED_BLOCK_PARSING;

        /* check size of output buffer  */
        if (*OutputSize_ptr < K - 3 - PSSize)
            return CRYS_RSA_15_ERROR_IN_DECRYPTED_DATA_SIZE;
        else
            *OutputSize_ptr = K - 3 - PSSize; /* output actual size of decrypted message */

        /* copy the message into output buffer */
        DX_PAL_MemCopy(Output_ptr, &EB_buff[3 + PSSize], *OutputSize_ptr);

        break;
#endif

#ifndef _INTERNAL_CRYS_NO_RSA_SCHEME_21_SUPPORT
    case CRYS_PKCS1_VER21:

        /* ------------------------------------------------*
         * Apply the EME-OAEP decoding operation to the   *
         * encoded message EM and the parameter          *
         * L to recover a message M:                      *
         * M = EME-OAEP-DECODE (EM, L)                    *
         * If the decoding operation outputs              *
         * "decoding error," then output                  *
         * "decryption error" and stop.                   *
         * ------------------------------------------------ */
        Error = CRYS_RSA_PSS_OAEPDecode(CrysHashOpMode, MGF, &EB_buff[1], (uint16_t)(K - 1), L, Llen, PrimeData_ptr,
                                        Output_ptr, OutputSize_ptr);
        break;
#endif
    default:
        return CRYS_RSA_PKCS1_VER_ARG_ERROR;
    }

#endif /* CRYS_NO_HASH_SUPPORT */
#endif /* CRYS_NO_PKI_SUPPORT */

    return Error;

} /* END OF _DX_RSA_SCHEMES_Decrypt */

#endif /* !defined(_INTERNAL_CRYS_NO_RSA_DECRYPT_SUPPORT) && !defined(_INTERNAL_CRYS_NO_RSA_SIGN_SUPPORT) */
