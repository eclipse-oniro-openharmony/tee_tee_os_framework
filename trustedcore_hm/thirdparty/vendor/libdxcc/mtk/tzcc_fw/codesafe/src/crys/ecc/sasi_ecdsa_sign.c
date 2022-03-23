/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_ASYM_ECC

/* ************ Include Files ************** */

/* .............. SaSi level includes ................. */
#include "ssi_pal_mem.h"
#include "sasi_ecpki_error.h"
#include "sasi_ecpki_local.h"
#include "sasi_ecpki_ecdsa.h"
#include "sasi_common.h"
#include "sasi_common_math.h"
#include "sasi_hash.h"
#include "sasi_rnd.h"
#include "sasi_rsa_types.h"
#include "sasi_fips_defs.h"

/* .............. LLF level includes ................. */
#include "pka_ecc_export.h"

/* canceling the lint warning:
   Warning 548: else expected */


/* canceling the lint warning:
Info 801: Use of goto is deprecated */


/* *********************** Defines *************************************** */
#if (SaSi_HASH_USER_CTX_SIZE_IN_WORDS > SaSi_PKA_RSA_HASH_CTX_SIZE_IN_WORDS)
#error SaSi_PKA_RSA_HASH_CTX_SIZE_IN_WORDS or SaSi_HASH_USER_CTX_SIZE_IN_WORDS  defined not correctly.
#endif

/* *********************** Enums ***************************************** */

/* *********************** Typedefs ************************************** */

/* *********************** Global Data *********************************** */

extern const ecpki_hash_t ecpki_hash_info[SaSi_ECPKI_HASH_NumOfModes];
extern const uint8_t ecpki_supported_hash_modes[SaSi_ECPKI_HASH_NumOfModes];
/* ************ Private function prototype ******************************* */

/* *********************** Public Functions ****************************** */

/* *************************************************************************
 *                  SaSi_ECDSA_Sign_Init function
 * *********************************************************************** */
/*
   \brief
   The SaSi_ECDSA_Sign_Init functions user shall call first to perform the
   EC DSA Signing operation.

   The function performs the following steps:
   -# Validates all the inputs of the function. If one of the received
      parameters is not valid, the function returns an error.
   -# Decrypts the received context to the working context after capturing
      the working context by calling the SaSi_CCM_GetContext() function.
   -# Initializes the working context and other variables and structures.
   -# Calls the SaSi_HASH_Init_MTK() function.
   -# Calls the SaSi_CCM_EncryptAndReleaseContext() function to encrypt
      the information in the working context, store it in the user's
      received context, and then release the working context.
   -# Exits the handler with the OK code.

   This function does not do ECDSA cryptographic processing. Rather, it
   prepares a context that is used by the Update() and Finish() functions.

   NOTE: Using of HASH functions with HASH size great, than EC modulus size, is not recommended!


   @param[in,out] pSignUserContext A pointer to the user buffer for signing data.
   @param[in]       pSignerPrivKey   A pointer to the private key that will be used to
                                      sign the data.
   @param[in]     hashMode            Defines the hash mode used for DSA.

   @return <b>SaSiError_t</b>: <br>
                         SaSi_OK<br>
                         SaSi_ECDSA_SIGN_INVALID_USER_CONTEXT_PTR_ERROR
                         SaSi_ECDSA_SIGN_INVALID_USER_PRIV_KEY_PTR_ERROR
                         SaSi_ECDSA_SIGN_USER_PRIV_KEY_VALIDATION_TAG_ERROR
                         SaSi_ECDSA_SIGN_INVALID_DOMAIN_ID_ERROR
                         SaSi_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR
*/
CEXPORT_C SaSiError_t SaSi_ECDSA_SignInit_MTK(SaSi_ECDSA_SignUserContext_t *pSignUserContext, /* in/out */
                                              SaSi_ECPKI_UserPrivKey_t *pSignerPrivKey,       /* in */
                                              SaSi_ECPKI_HASH_OpMode_t hashMode /* in */)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t err = SaSi_OK;
    /* defining a pointer to the active context allcated by the CCM */
    ECDSA_SignContext_t *pWorkingContext;

    /* FUNCTION LOGIC */

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context ID pointer is NULL return an error */
    if (pSignUserContext == NULL)
        return SaSi_ECDSA_SIGN_INVALID_USER_CONTEXT_PTR_ERROR;

    /* if the private key object is NULL return an error */
    if (pSignerPrivKey == NULL)
        return SaSi_ECDSA_SIGN_INVALID_USER_PRIV_KEY_PTR_ERROR;

    /* check if the hash operation mode is legal */
    if (hashMode >= SaSi_ECPKI_HASH_NumOfModes)
        return SaSi_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR;

    if (pSignerPrivKey->valid_tag != SaSi_ECPKI_PRIV_KEY_VALIDATION_TAG)
        return SaSi_ECDSA_SIGN_USER_PRIV_KEY_VALIDATION_TAG_ERROR;

    pWorkingContext = (ECDSA_SignContext_t *)&pSignUserContext->context_buff;

    /* reset the Context handler for improper previous values initialized */
    SaSi_PalMemSetZero(pWorkingContext, sizeof(ECDSA_SignContext_t));

    /* ................. loading the context .................................. */
    /* ------------------------------------------------------------------------ */

    /* Initializing the Hash operation mode in the ECDSA Context */
    if (hashMode > SaSi_ECPKI_HASH_NumOfModes) {
        err = SaSi_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR;
        goto End;
    }

    if (ecpki_supported_hash_modes[hashMode] == SASI_FALSE) {
        err = SaSi_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR;
        goto End;
    }

    pWorkingContext->hashMode            = hashMode;
    pWorkingContext->hashResultSizeWords = ecpki_hash_info[pWorkingContext->hashMode].hashResultSize;

    if (ecpki_hash_info[pWorkingContext->hashMode].hashMode < SaSi_HASH_NumOfModes) {
        err = SaSi_HASH_Init_MTK((SaSi_HASHUserContext_t *)(pWorkingContext->hashUserCtxBuff),
                                 ecpki_hash_info[pWorkingContext->hashMode].hashMode);
        if (err != SaSi_OK)
            goto End;
    }

    /* copy the ECPKI Private key to the context */
    SaSi_PalMemCopy(&pWorkingContext->ECDSA_SignerPrivKey, pSignerPrivKey, sizeof(SaSi_ECPKI_UserPrivKey_t));

    /* set the ECDSA validation tag */
    pSignUserContext->valid_tag = SaSi_ECDSA_SIGN_CONTEXT_VALIDATION_TAG;

End:
    /*  clear the users context in case of error */
    if (err != SaSi_OK) {
        SaSi_PalMemSetZero(pSignUserContext, sizeof(SaSi_ECDSA_SignUserContext_t));
    }

    return err;

} /* _DX_ECDSA_SignInit */

/* *************************************************************************
 *                  SaSi_ECDSA_Sign_Update function
 * *********************************************************************** */
/*
   @brief  Performs a hash  operation on data allocated by the user
           before finally signing it.

           In case user divides signing data by block, he must call the Update function
           continuously a number of times until processing of the entire data block is complete.

       NOTE: Using of HASH functions with HASH size great, than EC modulus size,
             is not recommended!

   @param [in,out] pSignUserContext - The pointer to the user buffer for signing the database.
   @param [in] pMessageDataIn - The pointer to the message data block for calculating the HASH.
   @param [in] dataInSize -  The size of the message data block, in bytes. The data size,
                   passed on each call of the function, besides the last call, must be a multiple of
                   the HASH block size according to used HASH mode.

   @return <b>SaSiError_t</b>: <br>
                         SaSi_OK<br>
                         SaSi_ECDSA_SIGN_INVALID_USER_CONTEXT_PTR_ERROR
                         SaSi_ECDSA_SIGN_USER_CONTEXT_VALIDATION_TAG_ERROR
                         SaSi_ECDSA_SIGN_INVALID_MESSAGE_DATA_IN_PTR_ERROR
                         SaSi_ECDSA_SIGN_INVALID_MESSAGE_DATA_IN_SIZE_ERROR
                         SaSi_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR
 */
CEXPORT_C SaSiError_t SaSi_ECDSA_SignUpdate_MTK(SaSi_ECDSA_SignUserContext_t *pSignUserContext, /* in/out */
                                                uint8_t *pMessageDataIn,                        /* in */
                                                uint32_t dataInSize /* in */)
{
    /* FUNCTION DECLERATIONS */

    /* The return error identifier */
    SaSiError_t err = SaSi_OK;

    /*  pointers to the inner contexts */
    ECDSA_SignContext_t *pWorkingContext;

    /* FUNCTION LOGIC */

    /* ....... checking the parameters validity ......... */
    /* -------------------------------------------------------------------- */

    /* if the users context pointer is NULL return an error */
    if (pSignUserContext == NULL)
        return SaSi_ECDSA_SIGN_INVALID_USER_CONTEXT_PTR_ERROR;

    /* if the users context TAG is illegal return an error - the context is invalid */
    if (pSignUserContext->valid_tag != SaSi_ECDSA_SIGN_CONTEXT_VALIDATION_TAG) {
        err = SaSi_ECDSA_SIGN_USER_CONTEXT_VALIDATION_TAG_ERROR;
        goto End;
    }

    /* if the users MessageDataIn pointer is illegal return an error */
    if (pMessageDataIn == NULL && dataInSize) {
        err = SaSi_ECDSA_SIGN_INVALID_MESSAGE_DATA_IN_PTR_ERROR;
        goto End;
    }

    /* check that the data size < 2^29 (to prevent an overflow on the
       transition to bits ) */
    if (dataInSize >= (1UL << 29)) {
        err = SaSi_ECDSA_SIGN_INVALID_MESSAGE_DATA_IN_SIZE_ERROR;
        goto End;
    }

    /* sign working context */
    pWorkingContext = (ECDSA_SignContext_t *)&pSignUserContext->context_buff;

    /* HASH update operations */
    if (ecpki_hash_info[pWorkingContext->hashMode].hashMode < SaSi_HASH_NumOfModes) {
        /* Operate the Hash update function for relevant version */
        err = SaSi_HASH_Update_MTK((SaSi_HASHUserContext_t *)(pWorkingContext->hashUserCtxBuff), pMessageDataIn,
                                   dataInSize);
        if (err != SaSi_OK) {
            goto End;
        }
    } else {
        if (dataInSize != pWorkingContext->hashResultSizeWords * sizeof(uint32_t)) {
            /* DataInSize must fit exactly to the size of Hash output that we support */
            err = SaSi_ECDSA_SIGN_INVALID_MESSAGE_DATA_IN_SIZE_ERROR;
            goto End;
        }
        /* Copy the DataIn_ptr to the HASH_Result */
        SaSi_PalMemCopy((uint8_t *)pWorkingContext->hashResult, pMessageDataIn, dataInSize);
    }

End:
    /*  clear the users context in case of error */
    if (err != SaSi_OK) {
        SaSi_PalMemSetZero(pSignUserContext, sizeof(SaSi_ECDSA_SignUserContext_t));
    }

    return err;

} /* SaSi_ECDSA_SignUpdate_MTK */

/* *************************************************************************
 *                  _DX_ECDSA_Sign_Finish function
 * *********************************************************************** */
/*
   @brief  Performs initialization of variables and structures, calls the hash function
           for the last block of data (if necessary) and then calculates digital signature.

           NOTE: Using of HASH functions with HASH size great, than EC modulus size,
                 is not recommended!
             Algorithm according ANS X9.62 standard

   @param[in] pSignUserContext -  A pointer to the user buffer for signing database.
   @param[in,out] pRndContext - A pointer to the random generation function context.
   @param[in] pSignatureOut - A pointer to a buffer for output of signature.
   @param[in,out] pSignatureOutSize- A pointer to the size of a user passed buffer
                     for signature (in), be not less than 2*orderSizeInBytes.
   @param[out] isEphemerKeyInternal - A parameter defining whether the ephemeral key
                     is internal or external (1 or 0).
   @param[out] pEphemerKeyData - A pointer to external ephemeral key data. If it is given
               (in case isEphemerKeyInternal=0), then the buffer must containing the
               ephemeral private key of size equal to EC generator order size, where
               LS-word is left most and MS-word is right most one.

   @return <b>SaSiError_t</b>: <br>
                         SaSi_OK<br>
                         SaSi_ECDSA_SIGN_INVALID_USER_CONTEXT_PTR_ERROR <br>
                         SaSi_ECDSA_SIGN_USER_CONTEXT_VALIDATION_TAG_ERROR <br>
                         SaSi_ECDSA_SIGN_INVALID_RND_CONTEXT_PTR_ERROR <br>
                         SaSi_ECDSA_SIGN_INVALID_SIGNATURE_OUT_PTR_ERROR <br>
                         SaSi_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR <br>
                         SaSi_ECDSA_SIGN_INVALID_SIGNATURE_OUT_SIZE_PTR_ERROR <br>
                         SaSi_ECDSA_SIGN_INVALID_SIGNATURE_OUT_SIZE_ERROR <br>
                         SaSi_ECDSA_SIGN_INVALID_IS_EPHEMER_KEY_INTERNAL_ERROR <br>
                         SaSi_ECDSA_SIGN_INVALID_EPHEMERAL_KEY_PTR_ERROR <br>
*/
CEXPORT_C SaSiError_t _DX_ECDSA_SignFinish_MTK(SaSi_ECDSA_SignUserContext_t *pSignUserContext, /* in */
                                               SaSi_RND_Context_t *pRndContext,                /* in/out */
                                               uint8_t *pSignOut,                              /* out */
                                               uint32_t *pSignOutSize,                         /* in/out */
                                               uint32_t isEphemerKeyInternal,                  /* in */
                                               uint32_t *pEphemerKeyData /* in */)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t err = SaSi_OK;

    /* pointer to the active context  */
    ECDSA_SignContext_t *pWorkingContext;

    /* pointer to private key structure in ccmWorkingContext  */
    SaSi_ECPKI_PrivKey_t *pPrivKey;
    /*  pointer to the current domain */
    SaSi_ECPKI_Domain_t *pDomain;

    uint32_t orderSizeInBytes, orderSizeInWords;
    /* Pointers to arguments for SaSi_ECDSA_SignCalc() primitive */
    uint32_t *pSignC, *pSignD;
    uint32_t *pMessRepres;
    uint32_t hashSizeWords;
    uint32_t *pTempBuff;

    /* FUNCTION LOGIC */

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* check the user context and RND context pointers */
    if (pSignUserContext == NULL)
        return SaSi_ECDSA_SIGN_INVALID_USER_CONTEXT_PTR_ERROR;
    if (pRndContext == NULL)
        return SaSi_ECDSA_SIGN_INVALID_RND_CONTEXT_PTR_ERROR;

    /* check the user's context tag  */
    if (pSignUserContext->valid_tag != SaSi_ECDSA_SIGN_CONTEXT_VALIDATION_TAG)
        return SaSi_ECDSA_SIGN_USER_CONTEXT_VALIDATION_TAG_ERROR;

    /* check the user's SignatureOut and SignatureOutSize pointers */
    if (pSignOut == NULL)
        return SaSi_ECDSA_SIGN_INVALID_SIGNATURE_OUT_PTR_ERROR;
    if (pSignOutSize == NULL)
        return SaSi_ECDSA_SIGN_INVALID_SIGNATURE_OUT_SIZE_PTR_ERROR;

    /* check isEphemerKeyInternal value and ephemeral key data pointer */
    if (isEphemerKeyInternal > 1)
        return SaSi_ECDSA_SIGN_INVALID_IS_EPHEMER_KEY_INTERNAL_ERROR;
    if (isEphemerKeyInternal == 0 && pEphemerKeyData == NULL)
        return SaSi_ECDSA_SIGN_INVALID_EPHEMERAL_KEY_PTR_ERROR;

    /* ............. checking the validity of context ........ */
    /* ------------------------------------------------------- */

    /* the pointer to the internal Sign context */
    pWorkingContext = (ECDSA_SignContext_t *)&pSignUserContext->context_buff;

    /* check Hash mode */
    if (pWorkingContext->hashMode >= SaSi_ECPKI_HASH_NumOfModes)
        return SaSi_ECDSA_SIGN_ILLEGAL_HASH_OP_MODE_ERROR;

    pPrivKey = (SaSi_ECPKI_PrivKey_t *)&pWorkingContext->ECDSA_SignerPrivKey.PrivKeyDbBuff;
    /* Initializing domain parameters */
    pDomain          = &pPrivKey->domain;
    orderSizeInBytes = CALC_FULL_BYTES(pDomain->ordSizeInBits);
    orderSizeInWords = CALC_FULL_32BIT_WORDS(pDomain->ordSizeInBits);
    hashSizeWords    = pWorkingContext->hashResultSizeWords;

    /* Temp buffers */
    pMessRepres = ((ecdsa_sign_db_t *)&pWorkingContext->sasiEcdsaSignIntBuff)->tempBuff;
    pSignC      = pMessRepres + orderSizeInWords;
    pSignD      = pSignC + orderSizeInWords;
    pTempBuff   = pSignD + orderSizeInWords;

    /* If the received output buffer is small than 2*orderSizeInBytes then return an error */
    if (*pSignOutSize < 2 * orderSizeInBytes)
        return SaSi_ECDSA_SIGN_INVALID_SIGNATURE_OUT_SIZE_ERROR;

    /* Operating the HASH Finish function; only if it is needed */
    if (pWorkingContext->hashMode <= SaSi_ECPKI_HASH_SHA512_mode) {
        err = SaSi_HASH_Finish_MTK((SaSi_HASHUserContext_t *)&pWorkingContext->hashUserCtxBuff,
                                   pWorkingContext->hashResult);
        if (err != SaSi_OK)
            goto End;
    }

    /* Derive message representative from HASH_Result: MessageRepresent =
       leftmost OrderSizeInBits bits of HASH_Result */

    /* Set 0 to MessageRepresent buffer of length OrdSizeInWords */
    SaSi_PalMemSetZero(pMessRepres, sizeof(uint32_t) * orderSizeInWords);

    /* Derive message representative = leftmost OrderSizeInBits bits of HASH_Result */
    /* Add change Endianness for BE CPU */
    if (pDomain->ordSizeInBits >= 32 * hashSizeWords) {
        SaSi_COMMON_ReverseMemcpy((uint8_t *)pMessRepres, (uint8_t *)(pWorkingContext->hashResult),
                                  sizeof(uint32_t) * hashSizeWords);
    } else {
        HostEcdsaTruncateMess(pMessRepres, (uint8_t *)(pWorkingContext->hashResult), pDomain->ordSizeInBits);
    }

    /* ********  Call LLF ECDSA Sinature function  ************ */
    err = LLF_ECDSA_SignCalcCall(pRndContext, pPrivKey, pMessRepres, isEphemerKeyInternal, pEphemerKeyData, pSignC,
                                 pSignD, pTempBuff);

    if (err != SaSi_OK)
        goto End;

    /* Output the reversed C,D strings of length orderSizeInBytes */
    err = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(pSignOut, orderSizeInBytes, pSignC, orderSizeInBytes);
    if (err != SaSi_OK)
        goto End;

    err = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(pSignOut + orderSizeInBytes, orderSizeInBytes, pSignD,
                                                      orderSizeInBytes);
    if (err != SaSi_OK)
        goto End;

    *pSignOutSize = 2 * orderSizeInBytes;

End:
    if (err != SaSi_OK) {
        SaSi_PalMemSetZero(pSignOut, (2 * orderSizeInBytes));
    }
    /* clear the users context  */
    SaSi_PalMemSetZero(pSignUserContext, sizeof(SaSi_ECDSA_SignUserContext_t));

    return err;

} /* _DX_ECDSA_SignFinish_MTK */

/* *************************************************************************
 *                  SaSi_ECDSA_Sign_MTK - integrated function
 * *********************************************************************** */
/*
   @brief  Performs all of the ECDSA signing operations simultaneously.

This function simply calls the Init, Update and Finish functions continuously.
               This function's prototype is similar to the prototypes of the called functions
               and includes all of their input and output arguments.

   NOTE: Signature lgorithm according ANS X9.62 standard
         Using of HASH functions with HASH size great, than EC modulus size, is not recommended!

   @param[in,out] pSignUserContext - A pointer to the user buffer for signing database.
   @param[in,out] pRndContext - A pointer to the random generation function context.
   @param[in]     pSignerPrivKey   - A pointer to a user private key structure.
   @param[in]     hashMode         - The enumerator variable defines hash function to be used.
   @param[in]       pMessageDataIn   - A message data for calculation of hash.
   @param[in]     messageSizeInBytes  - A size of block of message data in bytes.
   @param[in]     SignOut_ptr      - A pointer to a buffer for output of signature.
   @param[in,out] SignOutSize_ptr  - A pointer to the size of user passed buffer for signature (in)
                                        and size of actual signature (out). The size of buffer
                                        must be not less than 2*OrderSizeInBytes.

   @return <b>SaSiError_t
*/
CEXPORT_C SaSiError_t SaSi_ECDSA_Sign_MTK(SaSi_RND_Context_t *pRndContext,                /* in/out */
                                          SaSi_ECDSA_SignUserContext_t *pSignUserContext, /* in/out */
                                          SaSi_ECPKI_UserPrivKey_t *pSignerPrivKey,       /* in */
                                          SaSi_ECPKI_HASH_OpMode_t hashMode,              /* in */
                                          uint8_t *pMessageDataIn,                        /* in */
                                          uint32_t messageSizeInBytes,                    /* in */
                                          uint8_t *pSignOut,                              /* out */
                                          uint32_t *pSignOutSize /* in */)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t err = SaSi_OK;

    /* FUNCTION LOGIC */
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ****  SaSi_ECDSA_SignInit_MTK  ****** */
    err = SaSi_ECDSA_SignInit_MTK(pSignUserContext, pSignerPrivKey, hashMode);

    if (err != SaSi_OK)
        return err;

    /* ****  SaSi_ECDSA_SignUpdate_MTK  ****** */
    err = SaSi_ECDSA_SignUpdate_MTK(pSignUserContext, pMessageDataIn, messageSizeInBytes);
    if (err != SaSi_OK)
        return err;

    /* ****  SaSi_ECDSA_SignFinish  ****** */
    err = SaSi_ECDSA_SignFinish(pSignUserContext, pRndContext, pSignOut, pSignOutSize);
    return err;

} /* END OF SaSi_ECDSA_Sign_MTK */
