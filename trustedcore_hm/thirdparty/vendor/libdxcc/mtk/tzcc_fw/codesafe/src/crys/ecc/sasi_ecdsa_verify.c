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
#include "sasi_common.h"
#include "sasi_rsa_types.h"
#include "sasi_fips_defs.h"
#include "pka_ecc_export.h"

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
 *                  SaSi_ECDSA_VerifyInit_MTK  function
 * *********************************************************************** */
/*
   @brief  Prepares a context that is used by the Update and Finish functions
           but does not perform elliptic curve cryptographic processing

                    The function:
                        - Receives and decrypts user data (working context).
                        - Checks input parameters of  ECDSA Vrifying primitive.
                        - Calls hash init function.
                        - Initializes variables and structures for calling next functions.
                        - Encrypts and releases working context.

                        NOTE: Using of HASH functions with HASH size great, than EC modulus size,
                        is not recommended!

   @param[in,out] pVerifyUserContext - A pointer to the user buffer for verifying database.
   @param[in] pSignerPublKey - A pointer to a Signer public key structure.
   @param[in] hashMode - The enumerator variable defines the hash function to be used.

   @return <b>SaSiError_t</b>: <br>
                         SaSi_OK<br>
                         SaSi_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR <br>
                         SaSi_ECDSA_VERIFY_INVALID_SIGNER_PUBL_KEY_PTR_ERROR <br>
                         SaSi_ECDSA_VERIFY_SIGNER_PUBL_KEY_VALIDATION_TAG_ERROR <br>
                         SaSi_ECDSA_VERIFY_INVALID_DOMAIN_ID_ERROR <br>
                         SaSi_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR <br>
*/
CEXPORT_C SaSiError_t SaSi_ECDSA_VerifyInit_MTK(SaSi_ECDSA_VerifyUserContext_t *pVerifyUserContext, /* in/out */
                                                SaSi_ECPKI_UserPublKey_t *pSignerPublKey,           /* in */
                                                SaSi_ECPKI_HASH_OpMode_t hashMode /* in */)
{
    /* FUNCTION DECLERATIONS */

    /* The return error identifier */
    SaSiError_t err = SaSi_OK;
    /* defining a pointer to the active context allcated by the CCM */
    ECDSA_VerifyContext_t *pWorkingContext;

    /* FUNCTION LOGIC */

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context ID pointer is NULL return an error */
    if (pVerifyUserContext == NULL)
        return SaSi_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR;

    /* if the private key object is NULL return an error */
    if (pSignerPublKey == NULL)
        return SaSi_ECDSA_VERIFY_INVALID_SIGNER_PUBL_KEY_PTR_ERROR;

    /* check if the hash operation mode is legal */
    if (hashMode >= SaSi_ECPKI_HASH_NumOfModes)
        return SaSi_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR;

    if (pSignerPublKey->valid_tag != SaSi_ECPKI_PUBL_KEY_VALIDATION_TAG)
        return SaSi_ECDSA_VERIFY_SIGNER_PUBL_KEY_VALIDATION_TAG_ERROR;

    pWorkingContext = (ECDSA_VerifyContext_t *)&pVerifyUserContext->context_buff;

    /* reset the Context handler for improper previous values initialized */
    SaSi_PalMemSet(pWorkingContext, 0, sizeof(ECDSA_VerifyContext_t));

    /* ................. loading the context .................................. */
    /* ------------------------------------------------------------------------ */

    /* Initializing the Hash operation mode in the ECDSA Context */
    if (hashMode > SaSi_ECPKI_HASH_NumOfModes) {
        err = SaSi_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR;
        goto End;
    }

    if (ecpki_supported_hash_modes[hashMode] == SASI_FALSE) {
        err = SaSi_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR;
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

    /* copy the ECPKI Public key to the context */
    SaSi_PalMemCopy(&pWorkingContext->ECDSA_SignerPublKey, pSignerPublKey, sizeof(SaSi_ECPKI_UserPublKey_t));

    /* set the ECDSA validation tag */
    pVerifyUserContext->valid_tag = SaSi_ECDSA_VERIFY_CONTEXT_VALIDATION_TAG;

End:
    /*  clear the users context in case of error */
    if (err != SaSi_OK) {
        SaSi_PalMemSetZero(pVerifyUserContext, sizeof(SaSi_ECDSA_VerifyUserContext_t));
    }

    return err;

} /* _DX_ECDSA_VerifyInit */

/* *************************************************************************
 *                  SaSi_ECDSA_VerifyUpdate_MTK function
 * *********************************************************************** */
/*
   @brief  Performs a hash  operation on data allocated by the user
           before finally verifying its signature.

           In case user divides signing data by block, he must call the Update function
           continuously a number of times until processing of the entire data block is complete.

       NOTE: Using of HASH functions with HASH size greater, than EC modulus size,
             is not recommended.

   @param [in,out] pVerifyUserContext - The pointer to the user buffer for verifying database.
   @param [in] pMessageDataIn - The message data for calculating Hash.
   @param [in]dataInSize - The size of the message data block, in bytes. The data size,
                   passed on each call of the function, besides the last call, must be
                   a multiple of the HASH block size according to used HASH mode.

   @return <b>SaSiError_t</b>: <br>
                         SaSi_OK<br>
                         SaSi_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR <br>
                         SaSi_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR <br>
                         SaSi_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_PTR_ERROR <br>
                         SaSi_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_SIZE_ERROR <br>
                         SaSi_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR <br>
 */
CEXPORT_C SaSiError_t SaSi_ECDSA_VerifyUpdate_MTK(SaSi_ECDSA_VerifyUserContext_t *pVerifyUserContext, /* in/out */
                                                  uint8_t *pMessageDataIn,                            /* in */
                                                  uint32_t dataInSize /* in */)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t err = SaSi_OK;
    /* defining a pointer to the active context allcated by the CCM */
    ECDSA_VerifyContext_t *pWorkingContext;

    /* FUNCTION LOGIC */

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context pointer is NULL return an error */
    if (pVerifyUserContext == NULL)
        return SaSi_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR;

    /* if the users context TAG is illegal return an error - the context is invalid */
    if (pVerifyUserContext->valid_tag != SaSi_ECDSA_VERIFY_CONTEXT_VALIDATION_TAG)
        return SaSi_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR;

    /* if the users MessageDataIn pointer is illegal return an error */
    if (pMessageDataIn == NULL && dataInSize)
        return SaSi_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_PTR_ERROR;

    /* check that the data size < 2^29 (to prevent an overflow on the
       transition to bits ) */
    if (dataInSize >= (1UL << 29))
        return SaSi_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_SIZE_ERROR;

    /* sign working context */
    pWorkingContext = (ECDSA_VerifyContext_t *)&pVerifyUserContext->context_buff;

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
            err = SaSi_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_SIZE_ERROR;
            goto End;
        }
        /* Copy the DataIn_ptr to the HASH_Result */
        SaSi_PalMemCopy((uint8_t *)pWorkingContext->hashResult, pMessageDataIn, dataInSize);
    }

End:
    /*  clear the users context in case of error */
    if (err != SaSi_OK) {
        SaSi_PalMemSetZero(pVerifyUserContext, sizeof(SaSi_ECDSA_VerifyUserContext_t));
    }

    return err;

} /* SaSi_ECDSA_VerifyUpdate_MTK */

/* *************************************************************************
 *                  SaSi_ECDSA_VerifyFinish_MTK function
 * *********************************************************************** */
/*
   @brief  Performs initialization of variables and structures,
           calls the hash function for the last block of data (if necessary),
           than calls HostEcdsaVerify function for verifying signature
           according to EC DSA algorithm.

       NOTE: Using of HASH functions with HASH size greater, than EC modulus size,
             is not recommended!
             Algorithm according ANS X9.62 standard

   @param[in] pVerifyUserContext - A pointer to the user buffer for verifying the database.
   @param[in] pSignatureIn       - A pointer to a buffer for the signature to be compared
   @param[in] SignatureSizeBytes    - The size of a user passed signature (must be 2*orderSizeInBytes).

   @return <b>SaSiError_t</b>: <br>
              SaSi_OK <br>
                          SaSi_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR <br>
                          SaSi_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR <br>
                          SaSi_ECDSA_VERIFY_INVALID_SIGNATURE_IN_PTR_ERROR <br>
                          SaSi_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR <br>
                          SaSi_ECDSA_VERIFY_INVALID_SIGNATURE_SIZE_ERROR <br>
                          SaSi_ECDSA_VERIFY_INCONSISTENT_VERIFY_ERROR <br>
*/
CEXPORT_C SaSiError_t SaSi_ECDSA_VerifyFinish_MTK(SaSi_ECDSA_VerifyUserContext_t *pVerifyUserContext, /* in */
                                                  uint8_t *pSignatureIn,                              /* in */
                                                  uint32_t SignatureSizeBytes /* in */)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t err = SaSi_OK;

    /* pointer to the active context  */
    ECDSA_VerifyContext_t *pWorkingContext;
    /* pointer to public key structure in ccmWorkingContext  */
    struct SaSi_ECPKI_PublKey_t *PublKey_ptr;
    /*  EC domain ID and pointer to the current domain */
    /*  pointer to the current domain */
    SaSi_ECPKI_Domain_t *pDomain;

    uint32_t *pMessRepres, *pSignatureC, *pSignatureD;
    uint32_t hashSizeWords;
    uint32_t orderSizeInBytes, orderSizeInWords;

    /* FUNCTION LOGIC */

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context pointer is NULL return an error */
    if (pVerifyUserContext == NULL)
        return SaSi_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR;

    /* if the users context TAG is illegal return an error - the context is invalid */
    if (pVerifyUserContext->valid_tag != SaSi_ECDSA_VERIFY_CONTEXT_VALIDATION_TAG)
        return SaSi_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR;

    /* if the users Signature pointer is illegal then return an error */
    if (pSignatureIn == NULL)
        return SaSi_ECDSA_VERIFY_INVALID_SIGNATURE_IN_PTR_ERROR;

    /* ............. checking the validity of context ........ */
    /* ------------------------------------------------------- */

    /* the pointer to the internal Verify context */
    pWorkingContext = (ECDSA_VerifyContext_t *)&pVerifyUserContext->context_buff;

    /* check Hash mode */
    if (pWorkingContext->hashMode >= SaSi_ECPKI_HASH_NumOfModes)
        return SaSi_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR;

    PublKey_ptr = (struct SaSi_ECPKI_PublKey_t *)&pWorkingContext->ECDSA_SignerPublKey.PublKeyDbBuff;

    /* Initializing domain parameters */
    pDomain          = &PublKey_ptr->domain;
    orderSizeInBytes = CALC_FULL_BYTES(pDomain->ordSizeInBits);
    orderSizeInWords = CALC_FULL_32BIT_WORDS(pDomain->ordSizeInBits);

    /* if the user signature size is not equal to 2*ModSizeInBytes, then return an error */
    if (SignatureSizeBytes != 2 * orderSizeInBytes)
        return SaSi_ECDSA_VERIFY_INVALID_SIGNATURE_SIZE_ERROR;

    /* Operating the HASH Finish function only in case that Hash operation is needed */
    if (pWorkingContext->hashMode <= SaSi_ECPKI_HASH_SHA512_mode) {
        err = SaSi_HASH_Finish_MTK(((SaSi_HASHUserContext_t *)(pWorkingContext->hashUserCtxBuff)),
                                   pWorkingContext->hashResult);
        if (err != SaSi_OK)
            return err;
    }

    /*  Initialization of  HostEcdsaVerify arguments */
    hashSizeWords = pWorkingContext->hashResultSizeWords;
    /* Temp buffers */
    pSignatureC = ((ecdsa_verify_db_t *)(pWorkingContext->sasiEcdsaVerIntBuff))->tempBuff;
    pSignatureD = pSignatureC + orderSizeInWords; /* Max lengths of C in whole words */
    pMessRepres = pSignatureD + orderSizeInWords;

    // Check shortened cleaning
    /* Clean memory  */
    SaSi_PalMemSetZero(pSignatureC, 2 * 4 * orderSizeInWords); // -> pSignatureC[orderSizeInWords-1] = 0;
    // -> pSignatureD[orderSizeInWords-1] = 0;
    SaSi_PalMemSetZero(pMessRepres, 4 * orderSizeInWords); // -> pMessRepres[orderSizeInWords-1] = 0;

    /* Derive message representative = leftmost OrderSizeInBits bits of HASH_Result */
    if (pDomain->ordSizeInBits >= 32 * hashSizeWords) {
        SaSi_COMMON_ReverseMemcpy((uint8_t *)pMessRepres, (uint8_t *)(pWorkingContext->hashResult), 4 * hashSizeWords);
    } else {
        HostEcdsaTruncateMess(pMessRepres, (uint8_t *)(pWorkingContext->hashResult), pDomain->ordSizeInBits);
    }

    /* Convert signature data to words array with little entian order of  *
     *  words                                  */
    pSignatureC[orderSizeInWords - 1] = 0;
    SaSi_COMMON_ReverseMemcpy((uint8_t *)pSignatureC, pSignatureIn, orderSizeInBytes);
    pSignatureD[orderSizeInWords - 1] = 0;
    SaSi_COMMON_ReverseMemcpy((uint8_t *)pSignatureD, pSignatureIn + orderSizeInBytes, orderSizeInBytes);

    /* ------------------------------ */
    /* Verifying operation      */
    /* ------------------------------ */
    err = HostEcdsaVerify(PublKey_ptr, pMessRepres, orderSizeInWords, pSignatureC, pSignatureD);

    /* clear the users context  */
    SaSi_PalMemSetZero(pVerifyUserContext, sizeof(SaSi_ECDSA_VerifyUserContext_t));

    return err;

} /* End DX_ECDSA_VerifyFinish */

/* *************************************************************************
 *                  SaSi_ECDSA_Verify_MTK integrated function
 * *********************************************************************** */
/*
   @brief  Performs all ECDSA verifying operations simultaneously.

           This function simply calls the Init, Update and Finish functions continuously.

       NOTE: Using of HASH functions with HASH size great, than EC modulus size,
             is not recommended!
             Algorithm according ANS X9.62 standard


   @param[in]  pVerifyUserContext - A pointer to the user buffer for verifying database.
   @param[in]  pUserPublKey       - A pointer to a user public key structure.
   @param[in]  hashMode              - The enumerator variable defines the hash function to be used.
   @param[in]  pMessageDataIn     - Message data for calculating hash.
   @param[in]  messageSizeInBytes    - Size of block of message data in bytes.
   @param[in]  pSignatureIn       - A pointer to a buffer for output of signature.
   @param[in]  SignatureSizeBytes    - Size of signature, in bytes (must be 2*orderSizeInBytes).

   @return <b>SaSiError_t</b>: <br>
                        SaSi_OK <br>
                        SaSi_ECDSA_VERIFY_INVALID_USER_CONTEXT_PTR_ERROR <br>
                        SaSi_ECDSA_VERIFY_USER_CONTEXT_VALIDATION_TAG_ERROR <br>
                        SaSi_ECDSA_VERIFY_INVALID_DOMAIN_ID_ERROR <br>
                        SaSi_ECDSA_VERIFY_INVALID_SIGNER_PUBL_KEY_PTR_ERROR <br>
                        SaSi_ECDSA_VERIFY_SIGNER_PUBL_KEY_VALIDATION_TAG_ERROR <br>
                        SaSi_ECDSA_VERIFY_ILLEGAL_HASH_OP_MODE_ERROR <br>
                        SaSi_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_PTR_ERROR <br>
                        SaSi_ECDSA_VERIFY_INVALID_MESSAGE_DATA_IN_SIZE_ERROR <br>
                        SaSi_ECDSA_VERIFY_INVALID_SIGNATURE_IN_PTR_ERROR <br>
                        SaSi_ECDSA_VERIFY_INVALID_SIGNATURE_SIZE_ERROR <br>
                        SaSi_ECDSA_VERIFY_INCONSISTENT_VERIFY_ERROR <br>
*/
CEXPORT_C SaSiError_t SaSi_ECDSA_Verify_MTK(SaSi_ECDSA_VerifyUserContext_t *pVerifyUserContext, /* in/out */
                                            SaSi_ECPKI_UserPublKey_t *pUserPublKey,             /* in */
                                            SaSi_ECPKI_HASH_OpMode_t hashMode,                  /* in */
                                            uint8_t *pSignatureIn,                              /* in */
                                            uint32_t SignatureSizeBytes,                        /* in */
                                            uint8_t *pMessageDataIn,                            /* in */
                                            uint32_t messageSizeInBytes /* in */)
{
    /* FUNCTION DECLERATIONS */

    SaSiError_t err = SaSi_OK;

    /* FUNCTION LOGIC */
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    err = SaSi_ECDSA_VerifyInit_MTK(pVerifyUserContext, pUserPublKey, hashMode);

    if (err != SaSi_OK)
        return err;

    err = SaSi_ECDSA_VerifyUpdate_MTK(pVerifyUserContext, pMessageDataIn, messageSizeInBytes);
    if (err != SaSi_OK)
        return err;

    err = SaSi_ECDSA_VerifyFinish_MTK(pVerifyUserContext, pSignatureIn, SignatureSizeBytes);
    return err;

} /* END OF SaSi_ECDSA_Verify_MTK */
