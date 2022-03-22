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
#include <stdbool.h>
#include "crys.h"
#include "crys_rsa_error.h"
#include "crys_rsa_types.h"
#include "crys_ccm.h"
#include "crys_rsa_local.h"
#include "crys_bypass_api.h"
#include "cc_acl.h"

/* *********************** Defines **************************** */

/* canceling the lint warning:
   Use of goto is deprecated */

#if (CRYS_HASH_USER_CTX_SIZE_IN_WORDS > CRYS_PKA_RSA_HASH_CTX_SIZE_IN_WORDS)
#error CRYS_PKA_RSA_HASH_CTX_SIZE_IN_WORDS OR CRYS_HASH_USER_CTX_SIZE_IN_WORDS do not defined correctly.
#endif

/* *********************** Enums **************************** */
/* *********************** Typedefs ************************* */
/* *********************** Global Data ********************** */
/* ************ Private function prototype ****************** */

/* **************** Public Functions ************************ */

#ifndef _INTERNAL_CRYS_NO_RSA_SIGN_SUPPORT
/* ******************************************************************************************************* */
/*
   \brief RSA_SignInit initializes the Signing
   multi-call algorithm as defined in PKCS#1 v1.5 and 2.1

    The actual macro that will be used by the user is:
    CRYS_RSA_PSS_SignInit         - for v2.1
    CRYS_RSA_PKCS1v15_SignInit     - for v1.5

    NOTE: 1. In PSS_Sign v2.1 MD5 is not supported, since it is not recommended
         by the PKCS#1 v2.1.
          2. According to thesaid standard, implementation of the function
         for version v1.5 is based on DER encoding of the algorithm info.

   This function does not do cryptographic processing. Rather, it
   prepares a context that is used by the Update and Finish functions.

   @param[in,out] UserContext_ptr - A pointer to a Context. The value
                                returned here must be passed to
                                the Update and Finish functions.
   @param[in] UserPrivKey_ptr - A pointer to the private key data
                            structure. \note The representation
                            (pair or quintuple) and hence the
                            algorithm (CRT or not) is determined
                            by the Private Key data structure.
                            Using of the CRYS_Build_PrivKey
                            or CRYS_Build_PrivKeyCRT determines
                            which algorithm will be used.
   @param[in] rsaHashMode - The enumerator value, defining the hash function to be used:
             SHA-1SHA224/256/384/512, MD5 (MD5 allowed only in v1.5).
             The hash functions recommended by PKCS#1 v2.1 are:
                         256/384/512. Also allowed "After" HASH modes for said functions.
   @param[in] MGF - The mask generation function. PKCS#1 v2.1
                    defines MGF1, so the only value allowed here is CRYS_PKCS1_MGF1.
   @param[in] SaltLen - The Length of the Salt buffer (relevant for PKCS#1 Ver 2.1 only).
               Typical lengths are 0 and hLen (20 for SHA1).
               The maximum length allowed is NSize - hLen - 2.
   @param[in] PKCS1_ver - Ver 1.5 or 2.1, according to the functionality required.

   @return CRYSError_t - CRYS_OK, CRYS_BAD_PARAM
*/
CEXPORT_C CRYSError_t _DX_RSA_SignInit(CRYS_RSAPrivUserContext_t *UserContext_ptr,
                                       CRYS_RSAUserPrivKey_t *UserPrivKey_ptr, CRYS_RSA_HASH_OpMode_t rsaHashMode,
                                       CRYS_PKCS1_MGF_t MGF, uint16_t SaltLen, CRYS_PKCS1_version PKCS1_ver)
{
    /* FUNCTION DECLERATIONS */

    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;

    /* defining a pointer to the active context allcated by the CCM */
    RSAPrivContext_t *ccmWorkingContext_ptr;
    /* Pointer to the private key */
    CRYSRSAPrivKey_t *PrivKey_ptr;
    /* The modulus size in Octets */
    uint16_t ModulusSizeBytes = 0;

    /* FUNCTION LOGIC */

    /* ............... if not supported exit .............................. */
    /* -------------------------------------------------------------------- */

    RETURN_IF_RSA_UNSUPPORTED(UserContext_ptr, UserPrivKey_ptr, rsaHashMode, MGF, SaltLen, PKCS1_ver,
                              ccmWorkingContext_ptr, PrivKey_ptr, ModulusSizeBytes, Error, Error, Error, Error, Error,
                              Error, Error, Error, Error, Error, Error, Error, Error);

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context ID pointer is DX_NULL return an error */
    if (UserContext_ptr == DX_NULL)
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;

    /* if the private key object is DX_NULL return an error */
    if (UserPrivKey_ptr == DX_NULL)
        return CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR;

    /* check if the hash operation mode is legal */
    if (rsaHashMode >= CRYS_RSA_HASH_NumOfModes)
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

    /* check if the MGF operation mode is legal */
    if (CRYS_RSA_NumOfMGFFunctions <= MGF)
        return CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;

    /* check that the PKCS1 version argument is legal */
    if (PKCS1_ver >= CRYS_RSA_NumOf_PKCS1_versions)
        return CRYS_RSA_PKCS1_VER_ARG_ERROR;

    /* According to the PKCS1 ver 2.1 standard it is not recommended to use
         MD5 hash therefore we do not support it */
    if (PKCS1_ver == CRYS_PKCS1_VER21 && rsaHashMode == CRYS_RSA_HASH_MD5_mode)
        return CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;

    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ, UserPrivKey_ptr, sizeof(CRYS_RSAUserPrivKey_t)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, UserContext_ptr, sizeof(CRYS_RSAPrivUserContext_t))) {
        return CRYS_RSA_ILLEGAL_PARAMS_ACCORDING_TO_PRIV_ERROR;
    }

    if (UserPrivKey_ptr->valid_tag != CRYS_RSA_PRIV_KEY_VALIDATION_TAG)
        return CRYS_RSA_PRIV_KEY_VALIDATION_TAG_ERROR;

    if (PKCS1_ver == CRYS_PKCS1_VER21) {
        /* Initializing the Modulus Size in Bytes needed for SaltLength parameter check */
        PrivKey_ptr = (CRYSRSAPrivKey_t *)UserPrivKey_ptr->PrivateKeyDbBuff;

        /* Note: the (-1) is due to the PKCS#1 Ver2.1 standard section 9.1.1 */
        ModulusSizeBytes = (uint16_t)((PrivKey_ptr->nSizeInBits - 1) / 8);
        if ((PrivKey_ptr->nSizeInBits - 1) % 8)
            ModulusSizeBytes++;
    }

    /* .... aquiring the RSA context ...... */
    ccmWorkingContext_ptr = (RSAPrivContext_t *)UserContext_ptr->context_buff;

    /* Reset the Context handler for improper previous values initialized */
    DX_PAL_MemSet(UserContext_ptr, 0, sizeof(CRYS_RSAPrivUserContext_t));

    /* ................. loading the context .................................. */
    /* ------------------------------------------------------------------------ */

    /* Initializing the Hash operation mode in the RSA Context level */
    ccmWorkingContext_ptr->RsaHashOperationMode = rsaHashMode;
    ccmWorkingContext_ptr->doHash               = true; /* for actual Hash modes */
    ccmWorkingContext_ptr->HashBlockSize        = CRYS_HASH_BLOCK_SIZE_IN_WORDS;

    /*  Set HASH parameters */
    switch (ccmWorkingContext_ptr->RsaHashOperationMode) {
    case CRYS_RSA_After_HASH_NOT_KNOWN_mode:
        /* used for PKCS1 v1.5 Verify only - possible to derive the hash mode from the signature */
        if (PKCS1_ver == CRYS_PKCS1_VER21) {
            Error = CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
            goto END_WITH_ERROR;
        }
        ccmWorkingContext_ptr->doHash = false;
        break; /* do nothing */
    case CRYS_RSA_HASH_MD5_mode:
    case CRYS_RSA_After_MD5_mode:
        ccmWorkingContext_ptr->HASH_Result_Size  = CRYS_HASH_MD5_DIGEST_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashOperationMode = CRYS_HASH_MD5_mode;
        break;
    case CRYS_RSA_HASH_SHA1_mode:
    case CRYS_RSA_After_SHA1_mode:
        ccmWorkingContext_ptr->HASH_Result_Size  = CRYS_HASH_SHA1_DIGEST_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashOperationMode = CRYS_HASH_SHA1_mode;

        break;
    case CRYS_RSA_HASH_SHA224_mode:
    case CRYS_RSA_After_SHA224_mode:
        ccmWorkingContext_ptr->HASH_Result_Size  = CRYS_HASH_SHA224_DIGEST_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashOperationMode = CRYS_HASH_SHA224_mode;

        break;
    case CRYS_RSA_HASH_SHA256_mode:
    case CRYS_RSA_After_SHA256_mode:
        ccmWorkingContext_ptr->HASH_Result_Size  = CRYS_HASH_SHA256_DIGEST_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashOperationMode = CRYS_HASH_SHA256_mode;

        break;
    case CRYS_RSA_HASH_SHA384_mode:
    case CRYS_RSA_After_SHA384_mode:
        ccmWorkingContext_ptr->HASH_Result_Size  = CRYS_HASH_SHA384_DIGEST_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashBlockSize     = CRYS_HASH_SHA512_BLOCK_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashOperationMode = CRYS_HASH_SHA384_mode;

        break;
    case CRYS_RSA_HASH_SHA512_mode:
    case CRYS_RSA_After_SHA512_mode:
        ccmWorkingContext_ptr->HASH_Result_Size  = CRYS_HASH_SHA512_DIGEST_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashBlockSize     = CRYS_HASH_SHA512_BLOCK_SIZE_IN_WORDS;
        ccmWorkingContext_ptr->HashOperationMode = CRYS_HASH_SHA512_mode;

        break;
    default:
        Error = CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        goto END_WITH_ERROR;
    }

    /* set doHash for after Hash modes */
    switch (ccmWorkingContext_ptr->RsaHashOperationMode) {
    case CRYS_RSA_After_MD5_mode:
    case CRYS_RSA_After_SHA1_mode:
    case CRYS_RSA_After_SHA224_mode:
    case CRYS_RSA_After_SHA256_mode:
    case CRYS_RSA_After_SHA384_mode:
    case CRYS_RSA_After_SHA512_mode:
        ccmWorkingContext_ptr->doHash = false;
        break;
    default:
        break;
    }

    /* Init HASH */
    if (ccmWorkingContext_ptr->doHash) {
        Error = CRYS_HASH_Init(((CRYS_HASHUserContext_t *)((ccmWorkingContext_ptr->CRYSPKAHashCtxBuff))),
                               ccmWorkingContext_ptr->HashOperationMode);
        if (Error != CRYS_OK)
            goto END_WITH_ERROR;
    }

    /* Switch to appropriate PKCS1_version */
    /* ------------------------------------- */
    switch (PKCS1_ver) {
    case CRYS_PKCS1_VER15:
        ccmWorkingContext_ptr->PKCS1_Version = CRYS_PKCS1_VER15;
        break;

    case CRYS_PKCS1_VER21:
        /* Checking restriction of Salt Length ; Hash output size and the mosulus */
        if (ModulusSizeBytes < (uint32_t)(ccmWorkingContext_ptr->HASH_Result_Size * 4 + SaltLen + 2)) {
            Error = CRYS_RSA_PSS_ENCODING_MODULUS_HASH_SALT_LENGTHS_ERROR;
            goto END_WITH_ERROR;
        }
        ccmWorkingContext_ptr->PKCS1_Version = CRYS_PKCS1_VER21;
        break;

    default:
        Error = CRYS_RSA_PKCS1_VER_ARG_ERROR;
        goto END_WITH_ERROR;
    }

    /*  Set MGF indication */
    switch (MGF) {
    case CRYS_PKCS1_MGF1:
        ccmWorkingContext_ptr->MGF_2use = CRYS_PKCS1_MGF1;
        break;
    case CRYS_PKCS1_NO_MGF:
        ccmWorkingContext_ptr->MGF_2use = CRYS_PKCS1_NO_MGF;
        break;
    default:
        Error = CRYS_RSA_MGF_ILLEGAL_ARG_ERROR;
        goto END_WITH_ERROR;
    }

    /* Copying the RSA Private key argument to the context */
    DX_PAL_MemCopy((uint8_t *)&ccmWorkingContext_ptr->PrivUserKey, (uint8_t *)UserPrivKey_ptr,
                   sizeof(CRYS_RSAUserPrivKey_t));

    /* Initial the Salt random length relevant for PKCS#1 Ver2.1 */
    ccmWorkingContext_ptr->SaltLen = SaltLen;

    /* Set the RSA tag to the users context */
    UserContext_ptr->valid_tag = CRYS_RSA_SIGN_CONTEXT_VALIDATION_TAG;

    return Error;

END_WITH_ERROR:

    /* .... Clearing the users context in case of error ... */
    DX_PAL_MemSet(UserContext_ptr, 0, sizeof(CRYS_RSAPrivUserContext_t));

    return Error;

#endif /* !CRYS_NO_HASH_SUPPORT */
#endif /* !CRYS_NO_PKI_SUPPORT */

} /* _DX_RSA_SignInit */

/* ******************************************************************************************************* */
/*
   \brief CRYS_RSA_PSS_SignUpdate processes the data to be signed
   in a given context.

   \note RSA_PSS_SignUpdate can be called multiple times
   with data

    The actual macro that will be used by the users is (one of):
    CRYS_RSA_PSS_SignUpdate
    CRYS_RSA_PKCS1v15_SignUpdate

   \note CRYS_RSA_PSS_SignUpdate can be called multiple times
   with data

   @param[in] UserContext_ptr - A pointer to a valid context,
                as returned by CRYS_RSA_PSS_SignInit.
   @param[in] DataIn_ptr - A pointer to the data to sign.
   @param[in] DataInSize - The size, in bytes, of the data to sign.

   @return CRYSError_t - CRYS_OK, CRYS_BAD_PARAM
*/

CEXPORT_C CRYSError_t _DX_RSA_SignUpdate(CRYS_RSAPrivUserContext_t *UserContext_ptr, uint8_t *DataIn_ptr,
                                         uint32_t DataInSize)
{
    /* FUNCTION DECLERATIONS */

    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;

    /* defining a pointer to the active context allcated by the CCM */
    RSAPrivContext_t *ccmWorkingContext_ptr;

    /* FUNCTION LOGIC */

    /* ............... if not supported exit .............................. */
    /* -------------------------------------------------------------------- */

    RETURN_IF_RSA_UNSUPPORTED(UserContext_ptr, DataIn_ptr, DataInSize, ccmWorkingContext_ptr, Error, Error, Error,
                              Error, Error, Error, Error, Error, Error, Error, Error, Error, Error, Error, Error, Error,
                              Error, Error);

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context pointer is DX_NULL return an error */
    if (UserContext_ptr == DX_NULL)
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == DX_NULL && DataInSize)
        return CRYS_RSA_DATA_POINTER_INVALID_ERROR;

    /* if the data size is larger then 2^29 (to prevant an overflow on the transition to bits )
       return error */
    if (DataInSize >= (1 << 29))
        return CRYS_RSA_INVALID_MESSAGE_DATA_SIZE;

    /* DataIn can be smart pointer but it is tested either in the hash or in bypass operations */
    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, UserContext_ptr, sizeof(CRYS_RSAPrivUserContext_t)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ, DataIn_ptr, DataInSize)) {
        return CRYS_RSA_ILLEGAL_PARAMS_ACCORDING_TO_PRIV_ERROR;
    }

    /* if the users context TAG is illegal return an error - the context is invalid */
    if (UserContext_ptr->valid_tag != CRYS_RSA_SIGN_CONTEXT_VALIDATION_TAG)
        return CRYS_RSA_USER_CONTEXT_VALIDATION_TAG_ERROR;

    /* ....... aquiring the RSA context ........ */
    ccmWorkingContext_ptr = (RSAPrivContext_t *)&UserContext_ptr->context_buff;

    switch (ccmWorkingContext_ptr->RsaHashOperationMode) {
    /* The mode is either SHA1 or MD5 */
    case CRYS_RSA_HASH_SHA1_mode:
    case CRYS_RSA_HASH_MD5_mode:
    case CRYS_RSA_HASH_SHA224_mode:
    case CRYS_RSA_HASH_SHA256_mode:
    case CRYS_RSA_HASH_SHA384_mode:
    case CRYS_RSA_HASH_SHA512_mode:
        /* Operate the Hash update function for relevant versions */
        Error = CRYS_HASH_Update(((CRYS_HASHUserContext_t *)(ccmWorkingContext_ptr->CRYSPKAHashCtxBuff)), DataIn_ptr,
                                 DataInSize);

        if (Error != CRYS_OK)
            goto END_WITH_ERROR;
        break;

    case CRYS_RSA_After_SHA1_mode:
    case CRYS_RSA_After_MD5_mode:
    case CRYS_RSA_After_SHA224_mode:
    case CRYS_RSA_After_SHA256_mode:
    case CRYS_RSA_After_SHA384_mode:
    case CRYS_RSA_After_SHA512_mode:
        /* DataInSize must fit exactly to the size of Hash output that we support */
        if (DataInSize != ccmWorkingContext_ptr->HASH_Result_Size * sizeof(uint32_t)) {
            Error = CRYS_RSA_INVALID_MESSAGE_DATA_SIZE_IN_SSL_CASE;
            goto END_WITH_ERROR;
        }
        /* Copy the DataIn_ptr to the HashResult in case it is an SSL mode */
        Error = CRYS_Bypass(DataIn_ptr, DataInSize, (uint8_t *)ccmWorkingContext_ptr->HASH_Result);
        if (Error != CRYS_OK)
            goto END_WITH_ERROR;
        break;
    case CRYS_RSA_HASH_NO_HASH_mode:
        /* Do nothing */
        break;
    default:
        Error = CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR;
        goto END_WITH_ERROR;
    }

    return Error;

END_WITH_ERROR:

    /* .... clearing the users context in case of error .... */
    DX_PAL_MemSet(UserContext_ptr, 0, sizeof(CRYS_RSAPrivUserContext_t));

    return Error;

#endif /* !CRYS_NO_HASH_SUPPORT */
#endif /* !CRYS_NO_PKI_SUPPORT */

} /* _DX_RSA_SignUpdate */

/* ******************************************************************************************************* */
/*
   \brief _DX_RSA_SignFinish calculates the signature on the
   data passed to one or more calls to CRYS_RSA_PSS_SignUpdate,
   and releases the context.

    The actual macro that will be used by the user is:
    CRYS_RSA_PSS_SignFinish        - for v2.1
    CRYS_RSA_PKCS1v15_SignFinish    - for v1.5

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

   @return CRYSError_t - CRYS_OK,
             CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR,
             CRYS_RSA_USER_CONTEXT_VALIDATION_TAG_ERROR,
             CRYS_RSA_INVALID_OUTPUT_POINTER_ERROR,
             CRYS_RSA_INVALID_SIGNATURE_BUFFER_SIZE,
             CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR,
             CRYS_RSA_PKCS1_VER_ARG_ERROR
*/
CEXPORT_C CRYSError_t _DX_RSA_SignFinish(CRYS_RSAPrivUserContext_t *UserContext_ptr, uint8_t *Output_ptr,
                                         uint16_t *OutputSize_ptr)
{
    /* FUNCTION DECLERATIONS */

    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;
    /* defining a pointer to the active context allocated by the CCM */
    RSAPrivContext_t *ccmWorkingContext_ptr;
    /* The modulus size in Octets */
    uint16_t K;
    CRYSRSAPrivKey_t *PrivKey_ptr;

    /* FUNCTION LOGIC */

    /* ............... if not supported exit .............................. */
    /* -------------------------------------------------------------------- */

    RETURN_IF_RSA_UNSUPPORTED(UserContext_ptr, Output_ptr, OutputSize_ptr, ccmWorkingContext_ptr, K,
                              BerParserObj.DigestAlg, FormatedBlock_ptr, FormatedBlockSize_ptr, PrivKey_ptr, Error,
                              Error, Error, Error, Error, Error, Error, Error, Error, Error, Error, Error, Error);

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context pointer is DX_NULL return an error */
    if (UserContext_ptr == DX_NULL)
        return CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR;

    /* If the output pointer is DX_NULL return Error */
    if (Output_ptr == DX_NULL)
        return CRYS_RSA_INVALID_OUTPUT_POINTER_ERROR;

    /* If the output Size pointer is DX_NULL return Error */
    if (OutputSize_ptr == DX_NULL)
        return CRYS_RSA_INVALID_OUTPUT_SIZE_POINTER_ERROR;

    /* DataIn can be smart pointer but it is tested either in the hash or in bypass operations */
    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, UserContext_ptr, sizeof(CRYS_RSAPrivUserContext_t)) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, Output_ptr, *OutputSize_ptr) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, OutputSize_ptr, sizeof(uint32_t))) {
        return CRYS_RSA_ILLEGAL_PARAMS_ACCORDING_TO_PRIV_ERROR;
    }

    /* if the users context TAG is illegal return an error - the context is invalid */
    if (UserContext_ptr->valid_tag != CRYS_RSA_SIGN_CONTEXT_VALIDATION_TAG)
        return CRYS_RSA_USER_CONTEXT_VALIDATION_TAG_ERROR;

    /* ................. aquiring the RSA context ............................. */
    ccmWorkingContext_ptr = (RSAPrivContext_t *)&UserContext_ptr->context_buff;

    /* ......... checking the validity of the prameters in the context ........ */
    /* ------------------------------------------------------------------------ */

    PrivKey_ptr = (CRYSRSAPrivKey_t *)ccmWorkingContext_ptr->PrivUserKey.PrivateKeyDbBuff;

    /* Initializing the Modulus Size in Bytes */
    K = (uint16_t)((PrivKey_ptr->nSizeInBits + 7) / 8);

    /* If the received output buffer is small then return an error */
    if (*OutputSize_ptr < K) {
        Error = CRYS_RSA_INVALID_SIGNATURE_BUFFER_SIZE;
        goto END_WITH_ERROR;
    }

    /* Operating the HASH Finish function only in case that Hash operation is needed */
    if (ccmWorkingContext_ptr->doHash) {
        Error = CRYS_HASH_Finish(((CRYS_HASHUserContext_t *)(ccmWorkingContext_ptr->CRYSPKAHashCtxBuff)),
                                 ccmWorkingContext_ptr->HASH_Result);
        if (Error != CRYS_OK)
            goto END_WITH_ERROR;
    }

    /* ........................... execute the signiture ........................... */
    /* ----------------------------------------------------------------------------- */

    switch (ccmWorkingContext_ptr->PKCS1_Version) {
#ifndef _INTERNAL_CRYS_NO_RSA_SCHEME_21_SUPPORT
    case CRYS_PKCS1_VER21:

        Error = CRYS_RSA_PSS_Sign21(ccmWorkingContext_ptr, Output_ptr);
        if (Error != CRYS_OK)
            goto END_WITH_ERROR;
        /* set the output size to the modulus size */
        *OutputSize_ptr = K;
        break;
#endif

#ifndef _INTERNAL_CRYS_NO_RSA_SCHEME_15_SUPPORT
    case CRYS_PKCS1_VER15:

        /* The ouput size should be of the Modulus size = K */
        Error = DX_RSA_EMSA_PKCS1_v15_Encode(
            K, ccmWorkingContext_ptr->HashOperationMode, (uint8_t *)ccmWorkingContext_ptr->HASH_Result,
            ccmWorkingContext_ptr->HASH_Result_Size * sizeof(uint32_t), (uint8_t *)ccmWorkingContext_ptr->EBD);

        if (Error != CRYS_OK)
            goto END_WITH_ERROR;

        /* ..........    execute RSA encryption   .......... */
        Error = CRYS_RSA_PRIM_Decrypt(&ccmWorkingContext_ptr->PrivUserKey, &ccmWorkingContext_ptr->PrimeData,
                                      (uint8_t *)ccmWorkingContext_ptr->EBD, K, Output_ptr);

        if (Error != CRYS_OK)
            goto END_WITH_ERROR;
        /* set the output size to the modulus size */
        *OutputSize_ptr = K;

        break;
#endif
    default:
        Error = CRYS_RSA_PKCS1_VER_ARG_ERROR;
        goto END_WITH_ERROR;

    } /* end of (ccmWorkingContext_ptr->PKCS1_Version ) switch */

    return Error;

END_WITH_ERROR:

    /* .... clearing the users context in case of error  ... */
    DX_PAL_MemSet(UserContext_ptr, 0, sizeof(CRYS_RSAPrivUserContext_t));

    return Error;

#endif /* !CRYS_NO_HASH_SUPPORT */
#endif /* !CRYS_NO_PKI_SUPPORT */

} /* _DX_RSA_SignFinish */

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

   @param[in] UserContext_ptr - A pointer to a Context. For the use of the
                                   function as a space to work on.
   @param[in] UserPrivKey_ptr - A pointer to the private key data
                            structure of the user. \note The representation
                            (pair or quintuple) and hence the
                            algorithm (CRT or not) is determined
                            by the Private Key data
                            structure - using CRYS_Build_PrivKey
                            or CRYS_Build_PrivKeyCRT determines
                            which algorithm will be used.
   @param[in] hashFunc - The hash functions supported: SHA1, SHA-256/224/264/512, MD5
                         (MD5 - allowed only for PKCS#1 v1.5).
             Also allowed "After" HASH modes for said functions.
   @param[in] MGF - The mask generation function (enum). Only for PKCS#1 v2.1
                    defines MGF1, so the only value allowed for v2.1
                    is CRYS_PKCS1_MGF1.
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

   @return CRYSError_t - CRYS_OK,
                         CRYS_RSA_INVALID_USER_CONTEXT_POINTER_ERROR,
                         CRYS_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR,
                         CRYS_RSA_PRIV_KEY_VALIDATION_TAG_ERROR,
                         CRYS_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR,
                         CRYS_RSA_MGF_ILLEGAL_ARG_ERROR,
                         CRYS_RSA_PKCS1_VER_ARG_ERROR,
                         CRYS_RSA_INVALID_MESSAGE_DATA_SIZE,
                         CRYS_RSA_INVALID_OUTPUT_POINTER_ERROR,
                         CRYS_RSA_INVALID_SIGNATURE_BUFFER_SIZE
*/
CEXPORT_C CRYSError_t _DX_RSA_Sign(CRYS_RSAPrivUserContext_t *UserContext_ptr, CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                                   CRYS_RSA_HASH_OpMode_t rsaHashMode, CRYS_PKCS1_MGF_t MGF, uint16_t SaltLen,
                                   uint8_t *DataIn_ptr, uint32_t DataInSize, uint8_t *Output_ptr,
                                   uint16_t *OutputSize_ptr, CRYS_PKCS1_version PKCS1_ver)

{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    CRYSError_t Error = CRYS_OK;

    /* FUNCTION LOGIC */

    /* ............... if not supported exit .............................. */
    /* -------------------------------------------------------------------- */

    RETURN_IF_RSA_UNSUPPORTED(UserContext_ptr, UserPrivKey_ptr, rsaHashMode, MGF, SaltLen, DataIn_ptr, DataInSize,
                              Output_ptr, OutputSize_ptr, PKCS1_ver, Error, Error, Error, Error, Error, Error, Error,
                              Error, Error, Error, Error, Error);

#ifndef CRYS_NO_HASH_SUPPORT
#ifndef CRYS_NO_PKI_SUPPORT

    /* *********************************************************************
     *  RSA_SignInit
     * ******************************************************************* */
    Error = _DX_RSA_SignInit(UserContext_ptr, UserPrivKey_ptr, rsaHashMode, MGF, SaltLen, PKCS1_ver);
    if (Error != CRYS_OK)
        return Error;

    /* *********************************************************************
     *  RSA_SignUpdate
     * ******************************************************************* */
    Error = _DX_RSA_SignUpdate(UserContext_ptr, DataIn_ptr, DataInSize);
    if (Error != CRYS_OK)
        return Error;

    /* *********************************************************************
     * RSA_SignFinish
     * ******************************************************************* */
    Error = _DX_RSA_SignFinish(UserContext_ptr, Output_ptr, OutputSize_ptr);
    return Error;

#endif /* !CRYS_NO_HASH_SUPPORT */
#endif /* !CRYS_NO_PKI_SUPPORT */

} /* END OF _DX_RSA_Sign */

#endif /* _INTERNAL_CRYS_NO_RSA_SIGN_SUPPORT */
