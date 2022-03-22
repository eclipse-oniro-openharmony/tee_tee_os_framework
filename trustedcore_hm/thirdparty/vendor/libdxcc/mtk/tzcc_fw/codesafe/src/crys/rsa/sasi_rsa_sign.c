/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include "ssi_pal_mem.h"
#include <stdbool.h>
#include "sasi_rsa_prim.h"
#include "sasi_rsa_error.h"
#include "sasi_rsa_types.h"
#include "sasi_rsa_local.h"
#include "sasi_fips_defs.h"

/* *********************** Defines **************************** */

/* canceling the lint warning:
   Use of goto is deprecated */

#if (SaSi_HASH_USER_CTX_SIZE_IN_WORDS > SaSi_PKA_RSA_HASH_CTX_SIZE_IN_WORDS)
#error SaSi_PKA_RSA_HASH_CTX_SIZE_IN_WORDS OR SaSi_HASH_USER_CTX_SIZE_IN_WORDS do not defined correctly.
#endif

/* *********************** Enums **************************** */
/* *********************** Typedefs ************************* */
/* *********************** Global Data ********************** */
/* ************ Private function prototype ****************** */

/* **************** Public Functions ************************ */

#ifndef _INTERNAL_SaSi_NO_RSA_SIGN_SUPPORT
/* ******************************************************************************************************* */
/*
   \brief RSA_SignInit initializes the Signing
   multi-call algorithm as defined in PKCS#1 v1.5 and 2.1

    NOTE: 1. In PSS_Sign v2.1 MD5 is not supported, since it is not recommended
         by the PKCS#1 v2.1.
          2. According to thesaid standard, implementation of the function
         for version v1.5 is based on DER encoding of the algorithm info.

           This function does not do cryptographic processing. Rather, it
           prepares a context that is used by the Update and Finish functions.

   @param[in,out] UserContext_ptr - A pointer to a Context. The value returned here
                                must be passed to the Update and Finish functions.
   @param[in] UserPrivKey_ptr - A pointer to the private key data structure.
                  \note The representation (pair or quintuple) and hence the
                  algorithm (CRT or not) is determined by the Private Key data structure.
                  Using of the SaSi_Build_PrivKey or SaSi_Build_PrivKeyCRT determines
                  which algorithm will be used.
   @param[in] rsaHashMode - The enumerator value, defining the hash function to be used:
             SHA-1SHA224/256/384/512, MD5 (MD5 allowed only in v1.5).
             The hash functions recommended by PKCS#1 v2.1 are:
                         256/384/512. Also allowed "After" HASH modes for said functions.
   @param[in] MGF - The mask generation function. PKCS#1 v2.1
                    defines MGF1, so the only value allowed here is SaSi_PKCS1_MGF1.
   @param[in] SaltLen - The Length of the Salt buffer (relevant for PKCS#1 Ver 2.1 only,
                        typically lengths is 0 or hLen). FIPS 186-4 requires, that SaltLen <= hlen.
                        If SaltLen > KeySize - hLen - 2, the function returns an error.
   @param[in] PKCS1_ver - Ver 1.5 or 2.1, according to the functionality required.

   @return SaSiError_t - SaSi_OK, SaSi_BAD_PARAM
*/
CEXPORT_C SaSiError_t SaSi_RsaSignInit(SaSi_RSAPrivUserContext_t *UserContext_ptr,
                                       SaSi_RSAUserPrivKey_t *UserPrivKey_ptr, SaSi_RSA_HASH_OpMode_t rsaHashMode,
                                       SaSi_PKCS1_MGF_t MGF, uint16_t SaltLen, SaSi_PKCS1_version PKCS1_ver)
{
    /* FUNCTION DECLERATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    /* defining a pointer to the active context allcated by the CCM */
    RSAPrivContext_t *ccmWorkingContext_ptr;
    /* Pointer to the private key */
    SaSiRSAPrivKey_t *PrivKey_ptr;
    /* The modulus size in Octets */
    uint16_t ModulusSizeBytes = 0;

    /* FUNCTION LOGIC */

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context ID pointer is NULL return an error */
    if (UserContext_ptr == NULL)
        return SaSi_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;

    /* if the private key object is NULL return an error */
    if (UserPrivKey_ptr == NULL)
        return SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* check if the hash operation mode is legal */
    if (rsaHashMode >= SaSi_RSA_HASH_NumOfModes)
        return SaSi_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

    /* check if the MGF operation mode is legal */
    if (SaSi_RSA_NumOfMGFFunctions <= MGF)
        return SaSi_RSA_MGF_ILLEGAL_ARG_ERROR;

    /* check that the PKCS1 version argument is legal */
    if (PKCS1_ver >= SaSi_RSA_NumOf_PKCS1_versions)
        return SaSi_RSA_PKCS1_VER_ARG_ERROR;

    if (UserPrivKey_ptr->valid_tag != SaSi_RSA_PRIV_KEY_VALIDATION_TAG)
        return SaSi_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

    /* According to the PKCS1 ver 2.1 standard it is not recommended to use
         MD5 hash therefore we do not support it */
    if (PKCS1_ver == SaSi_PKCS1_VER21 && rsaHashMode == SaSi_RSA_HASH_MD5_mode)
        return SaSi_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

    if (PKCS1_ver == SaSi_PKCS1_VER21) {
        /* Initializing the Modulus Size in Bytes needed for SaltLength parameter check */
        PrivKey_ptr = (SaSiRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

        /* Note: the (-1) is due to the PKCS#1 Ver2.1 standard section 9.1.1 */
        ModulusSizeBytes = (uint16_t)((PrivKey_ptr->nSizeInBits - 1) / 8);
        if ((PrivKey_ptr->nSizeInBits - 1) % 8)
            ModulusSizeBytes++;
    }

    /* .... aquiring the RSA context ...... */
    ccmWorkingContext_ptr = (RSAPrivContext_t *)((void *)UserContext_ptr->context_buff);

    /* Reset the Context handler for improper previous values initialized */
    SaSi_PalMemSetZero(UserContext_ptr, sizeof(SaSi_RSAPrivUserContext_t));

    /* ................. loading the context .................................. */
    /* ------------------------------------------------------------------------ */

    /* Initializing the Hash operation mode in the RSA Context level */
    ccmWorkingContext_ptr->RsaHashOperationMode = rsaHashMode;

    if (rsa_supported_hash_modes[rsaHashMode] == SASI_FALSE) {
        Error = SaSi_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        goto End;
    }

    ccmWorkingContext_ptr->HashOperationMode = rsa_hash_info[rsaHashMode].hashMode;
    ccmWorkingContext_ptr->HASH_Result_Size  = rsa_hash_info[rsaHashMode].hashResultSize;

    if ((ccmWorkingContext_ptr->HashOperationMode == SaSi_HASH_SHA384_mode) ||
        (ccmWorkingContext_ptr->HashOperationMode == SaSi_HASH_SHA512_mode))
        ccmWorkingContext_ptr->HashBlockSize = SaSi_HASH_SHA512_BLOCK_SIZE_IN_WORDS;
    else
        ccmWorkingContext_ptr->HashBlockSize = SaSi_HASH_BLOCK_SIZE_IN_WORDS;

    if ((rsaHashMode == SaSi_RSA_HASH_MD5_mode) || (rsaHashMode == SaSi_RSA_HASH_SHA1_mode) ||
        (rsaHashMode == SaSi_RSA_HASH_SHA224_mode) || (rsaHashMode == SaSi_RSA_HASH_SHA256_mode) ||
        (rsaHashMode == SaSi_RSA_HASH_SHA384_mode) || (rsaHashMode == SaSi_RSA_HASH_SHA512_mode))
        ccmWorkingContext_ptr->doHash = true; /* for actual Hash modes */
    else
        ccmWorkingContext_ptr->doHash = false;

    /* Init HASH */
    if (ccmWorkingContext_ptr->doHash) {
        Error = SaSi_HASH_Init_MTK(((SaSi_HASHUserContext_t *)((ccmWorkingContext_ptr->SaSiPKAHashCtxBuff))),
                                   ccmWorkingContext_ptr->HashOperationMode);
        if (Error != SaSi_OK)
            goto End;
    }

    /* Switch to appropriate PKCS1_version */
    /* ------------------------------------- */
    switch (PKCS1_ver) {
    case SaSi_PKCS1_VER15:
        ccmWorkingContext_ptr->PKCS1_Version = SaSi_PKCS1_VER15;
        break;

    case SaSi_PKCS1_VER21:
        /* Checking restriction of Salt Length ; Hash output size and the mosulus */
        if (ModulusSizeBytes < (uint32_t)(ccmWorkingContext_ptr->HASH_Result_Size * 4 + SaltLen + 2)) {
            Error = SaSi_RSA_PSS_ENCODING_MODULUS_HASH_SALT_LENGTHS_ERROR;
            goto End;
        }
        ccmWorkingContext_ptr->PKCS1_Version = SaSi_PKCS1_VER21;
        break;

    default:
        Error = SaSi_RSA_PKCS1_VER_ARG_ERROR;
        goto End;
    }

    /*  Set MGF indication */
    switch (MGF) {
    case SaSi_PKCS1_MGF1:
        ccmWorkingContext_ptr->MGF_2use = SaSi_PKCS1_MGF1;
        break;
    case SaSi_PKCS1_NO_MGF:
        ccmWorkingContext_ptr->MGF_2use = SaSi_PKCS1_NO_MGF;
        break;
    default:
        Error = SaSi_RSA_MGF_ILLEGAL_ARG_ERROR;
        goto End;
    }

    /* Copying the RSA Private key argument to the context */
    SaSi_PalMemCopy((uint8_t *)&ccmWorkingContext_ptr->PrivUserKey, (uint8_t *)UserPrivKey_ptr,
                    sizeof(SaSi_RSAUserPrivKey_t));

    /* Initial the Salt random length relevant for PKCS#1 Ver2.1 */
    ccmWorkingContext_ptr->SaltLen = SaltLen;

    /* Set the RSA tag to the users context */
    UserContext_ptr->valid_tag = SaSi_RSA_SIGN_CONTEXT_VALIDATION_TAG;

End:

    /* .... Clearing the users context in case of error ... */
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(UserContext_ptr, sizeof(SaSi_RSAPrivUserContext_t));
    }

    return Error;

} /* SaSi_RsaSignInit */

/* ******************************************************************************************************* */
/*
   \brief SaSi_RsaSignUpdate processes the data to be signed
   in a given context.

   \note SaSi_RsaSignUpdate can be called multiple times
   with data

   @param[in] UserContext_ptr - A pointer to a valid context,
                as returned by SaSi_RsaSignInit.
   @param[in] DataIn_ptr - A pointer to the data to sign.
   @param[in] DataInSize - The size, in bytes, of the data to sign.

   @return SaSiError_t - SaSi_OK, SaSi_BAD_PARAM
*/

CEXPORT_C SaSiError_t SaSi_RsaSignUpdate(SaSi_RSAPrivUserContext_t *UserContext_ptr, uint8_t *DataIn_ptr,
                                         uint32_t DataInSize)
{
    /* FUNCTION DECLERATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    /* defining a pointer to the active context allcated by the CCM */
    RSAPrivContext_t *ccmWorkingContext_ptr;

    /* FUNCTION LOGIC */

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context pointer is NULL return an error */
    if (UserContext_ptr == NULL)
        return SaSi_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == NULL && DataInSize) {
        Error = SaSi_RSA_DATA_POINTER_INVALID_ERROR;
        goto End;
    }

    /* if the data size is larger then 2^29 (to prevant an overflow on the transition to bits )
       return error */
    if (DataInSize >= (1 << 29)) {
        Error = SaSi_RSA_INVALID_MESSAGE_DATA_SIZE;
        goto End;
    }

    /* if the users context TAG is illegal return an error - the context is invalid */
    if (UserContext_ptr->valid_tag != SaSi_RSA_SIGN_CONTEXT_VALIDATION_TAG) {
        Error = SaSi_RSA_USER_CONTEXT_VALIDATION_TAG_ERROR;
        goto End;
    }

    /* ....... aquiring the RSA context ........ */
    ccmWorkingContext_ptr = (RSAPrivContext_t *)((void *)&UserContext_ptr->context_buff);

    if (ccmWorkingContext_ptr->doHash) {
        /* Operate the Hash update function for relevant versions */
        Error = SaSi_HASH_Update_MTK(((SaSi_HASHUserContext_t *)(ccmWorkingContext_ptr->SaSiPKAHashCtxBuff)),
                                     DataIn_ptr, DataInSize);

        if (Error != SaSi_OK)
            goto End;
    } else {
        /* DataInSize must fit exactly to the size of Hash output that we support */
        if (DataInSize != ccmWorkingContext_ptr->HASH_Result_Size * sizeof(uint32_t)) {
            Error = SaSi_RSA_INVALID_MESSAGE_DATA_SIZE_IN_SSL_CASE;
            goto End;
        }
        /* Copy the DataIn_ptr to the HashResult in case it is an SSL mode */
        SaSi_PalMemCopy((uint8_t *)ccmWorkingContext_ptr->HASH_Result, DataIn_ptr, DataInSize);
    }

End:

    /* .... clearing the users context in case of error .... */
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(UserContext_ptr, sizeof(SaSi_RSAPrivUserContext_t));
    }

    return Error;

} /* SaSi_RsaSignUpdate */

/* ******************************************************************************************************* */
/*
   \brief SaSi_RsaSignFinish calculates the signature on the
   data passed to one or more calls to SaSi_RsaSignUpdate,
   and releases the context.

   @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
   @param[in,out] UserContext_ptr - A pointer to the Context
                initialized by the SignInit function
                and used by the SignUpdate function
   @param[out] Output_ptr - A pointer to the signature.
                The buffer must be at least PrivKey_ptr->N.len bytes long
                (that is, the size of the modulus, in bytes).
   @param[in,out] OutputSize_ptr - A pointer to the Signature Size value - the input value
                   is the signature buffer size allocated, the output value is
                   the signature size used.
                   The buffer must be at least PrivKey_ptr->N.len bytes long
                   (that is, the size of the modulus, in bytes).

   @return SaSiError_t - SaSi_OK,
             SaSi_RSA_INVALID_USER_CONTEXT_POINTER_ERROR,
             SaSi_RSA_USER_CONTEXT_VALIDATION_TAG_ERROR,
             SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR,
             SaSi_RSA_INVALID_SIGNATURE_BUFFER_SIZE,
             SaSi_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR,
             SaSi_RSA_PKCS1_VER_ARG_ERROR
*/
CEXPORT_C SaSiError_t SaSi_RsaSignFinish(SaSi_RND_Context_t *rndContext_ptr, SaSi_RSAPrivUserContext_t *UserContext_ptr,
                                         uint8_t *Output_ptr, uint16_t *OutputSize_ptr)
{
    /* FUNCTION DECLERATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;
    /* defining a pointer to the active context allocated by the CCM */
    RSAPrivContext_t *ccmWorkingContext_ptr;
    /* The modulus size in Octets */
    uint16_t K;
    SaSiRSAPrivKey_t *PrivKey_ptr;

    /* FUNCTION LOGIC */

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context pointer is NULL return an error */
    if (UserContext_ptr == NULL)
        return SaSi_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;

    /* If the output pointer is NULL return Error */
    if (Output_ptr == NULL) {
        Error = SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR;
        goto End1;
    }

    /* If the output Size pointer is NULL return Error */
    if (OutputSize_ptr == NULL) {
        Error = SaSi_RSA_INVALID_OUTPUT_SIZE_POINTER_ERROR;
        goto End1;
    }

    /* if the users context TAG is illegal return an error - the context is invalid */
    if (UserContext_ptr->valid_tag != SaSi_RSA_SIGN_CONTEXT_VALIDATION_TAG) {
        Error = SaSi_RSA_USER_CONTEXT_VALIDATION_TAG_ERROR;
        goto End1;
    }

    /* ................. aquiring the RSA context ............................. */
    ccmWorkingContext_ptr = (RSAPrivContext_t *)((void *)&UserContext_ptr->context_buff);

    /* ......... checking the validity of the prameters in the context ........ */
    /* ------------------------------------------------------------------------ */

    PrivKey_ptr = (SaSiRSAPrivKey_t *)ccmWorkingContext_ptr->PrivUserKey.PrivateKeyDbBuff;

    /* Initializing the Modulus Size in Bytes */
    K = (uint16_t)CALC_FULL_BYTES(PrivKey_ptr->nSizeInBits);

    /* If the received output buffer is small then return an error */
    if (*OutputSize_ptr < K) {
        Error = SaSi_RSA_INVALID_SIGNATURE_BUFFER_SIZE;
        goto End1;
    }

    /* Operating the HASH Finish function only in case that Hash operation is needed */
    if (ccmWorkingContext_ptr->doHash) {
        Error = SaSi_HASH_Finish_MTK(((SaSi_HASHUserContext_t *)(ccmWorkingContext_ptr->SaSiPKAHashCtxBuff)),
                                     ccmWorkingContext_ptr->HASH_Result);
        if (Error != SaSi_OK)
            goto End;
    }

    /* ........................... execute the signiture ........................... */
    /* ----------------------------------------------------------------------------- */

    switch (ccmWorkingContext_ptr->PKCS1_Version) {
#ifndef _INTERNAL_SaSi_NO_RSA_SCHEME_21_SUPPORT
    case SaSi_PKCS1_VER21:

        Error = SaSi_RSA_PSS_Sign21(rndContext_ptr, ccmWorkingContext_ptr, Output_ptr);
        if (Error != SaSi_OK)
            goto End;
        /* set the output size to the modulus size */
        *OutputSize_ptr = K;
        break;
#endif

#ifndef _INTERNAL_SaSi_NO_RSA_SCHEME_15_SUPPORT
    case SaSi_PKCS1_VER15:

        /* The ouput size should be of the Modulus size = K */
        Error = SaSi_RsaEmsaPkcs1v15Encode(
            K, ccmWorkingContext_ptr->HashOperationMode, (uint8_t *)ccmWorkingContext_ptr->HASH_Result,
            ccmWorkingContext_ptr->HASH_Result_Size * sizeof(uint32_t), (uint8_t *)ccmWorkingContext_ptr->EBD);

        if (Error != SaSi_OK)
            goto End;

        /* ..........    execute RSA encryption   .......... */
        Error = SaSi_RSA_PRIM_Decrypt_MTK(&ccmWorkingContext_ptr->PrivUserKey, &ccmWorkingContext_ptr->PrimeData,
                                          (uint8_t *)ccmWorkingContext_ptr->EBD, K, Output_ptr);

        if (Error != SaSi_OK)
            goto End;
        /* set the output size to the modulus size */
        *OutputSize_ptr = K;

        break;
#endif
    default:
        Error = SaSi_RSA_PKCS1_VER_ARG_ERROR;
        goto End;

    } /* end of (ccmWorkingContext_ptr->PKCS1_Version ) switch */

End:
    if (Error != SaSi_OK) {
        SaSi_PalMemSetZero(Output_ptr, *OutputSize_ptr);
        *OutputSize_ptr = 0;
    }

End1:
    /* .... clearing the users context in case of error  ... */
    SaSi_PalMemSetZero(UserContext_ptr, sizeof(SaSi_RSAPrivUserContext_t));

    return Error;

} /* SaSi_RsaSignFinish */

/* ******************************************************************************************************* */
/*
   @brief
   \brief RSA_Sign implements the RSASSA-PKCS1v15 algorithm
    in a single function as defined in PKCS#1 v2.1 standard, including v1.5.

    The user can call the function by appropriate macro according to choosen
    (and allowed) HASH algorithm SHA1, SHA224... (see macros below).

    NOTE: 1. In PSS_Sign v2.1 MD5 is not supported, since it is not recommended
         by the PKCS#1 v2.1.
          2. According to thesaid standard, implementation of the function
         for version v1.5 is based on DER encoding of the algorithm info.

   @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
   @param[in] UserContext_ptr - A pointer to a Context. For the use of the
                                   function as a space to work on.
   @param[in] UserPrivKey_ptr - A pointer to the private key data
                            structure of the user. \note The representation
                            (pair or quintuple) and hence the
                            algorithm (CRT or not) is determined
                            by the Private Key data
                            structure - using SaSi_Build_PrivKey
                            or SaSi_Build_PrivKeyCRT determines
                            which algorithm will be used.
   @param[in] hashFunc - The hash functions supported: SHA1, SHA-256/224/264/512, MD5
                         (MD5 - allowed only for PKCS#1 v1.5).
             Also allowed "After" HASH modes for said functions.
   @param[in] MGF - The mask generation function (enum). Only for PKCS#1 v2.1
                    defines MGF1, so the only value allowed for v2.1
                    is SaSi_PKCS1_MGF1.
   @param[in] SaltLen - The Length of the Salt buffer (relevant for PKCS#1 Ver 2.1 only)
               Typical lengths are 0 and hLen (20 for SHA1)
               The maximum length allowed is NSize - hLen - 2.
   @param[in] DataIn_ptr - A pointer to the data to sign.
   @param[in] DataInSize - The size, in bytes, of the data to sign.
   @param[out] Output_ptr - A pointer to the signature.
                            The buffer must be at least PrivKey_ptr->N.len bytes long
                            (that is, the size of the modulus in bytes).
   @param[in,out] OutputSize_ptr - A pointer to the Signature Size value - the input value
                            is the signature buffer size allocated, the output value is
                            the signature size actually used.
                            The buffer must be at least PrivKey_ptr->N.len bytes long
                            (that is, the size of the modulus in bytes).
   @param[in] PKCS1_ver - Ver 1.5 or 2.1, according to the functionality required

   @return SaSiError_t - SaSi_OK,
                         SaSi_RSA_INVALID_USER_CONTEXT_POINTER_ERROR,
                         SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
                         SaSi_RSA_PRIV_KEY_VALIDATION_TAG_ERROR,
                         SaSi_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR,
                         SaSi_RSA_MGF_ILLEGAL_ARG_ERROR,
                         SaSi_RSA_PKCS1_VER_ARG_ERROR,
                         SaSi_RSA_INVALID_MESSAGE_DATA_SIZE,
                         SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR,
                         SaSi_RSA_INVALID_SIGNATURE_BUFFER_SIZE
*/
CEXPORT_C SaSiError_t SaSi_RsaSign(SaSi_RND_Context_t *rndContext_ptr, SaSi_RSAPrivUserContext_t *UserContext_ptr,
                                   SaSi_RSAUserPrivKey_t *UserPrivKey_ptr, SaSi_RSA_HASH_OpMode_t rsaHashMode,
                                   SaSi_PKCS1_MGF_t MGF, uint16_t SaltLen, uint8_t *DataIn_ptr, uint32_t DataInSize,
                                   uint8_t *Output_ptr, uint16_t *OutputSize_ptr, SaSi_PKCS1_version PKCS1_ver)

{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    /* FUNCTION LOGIC */

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* *********************************************************************
     *  RSA_SignInit
     * ******************************************************************* */
    Error = SaSi_RsaSignInit(UserContext_ptr, UserPrivKey_ptr, rsaHashMode, MGF, SaltLen, PKCS1_ver);
    if (Error != SaSi_OK)
        return Error;

    /* *********************************************************************
     *  RSA_SignUpdate
     * ******************************************************************* */
    Error = SaSi_RsaSignUpdate(UserContext_ptr, DataIn_ptr, DataInSize);
    if (Error != SaSi_OK)
        return Error;

    /* *********************************************************************
     * RSA_SignFinish
     * ******************************************************************* */
    Error = SaSi_RsaSignFinish(rndContext_ptr, UserContext_ptr, Output_ptr, OutputSize_ptr);
    return Error;

} /* END OF SaSi_RsaSign */

#endif /* _INTERNAL_SaSi_NO_RSA_SIGN_SUPPORT */
